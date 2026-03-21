// Package client provides NoizDNS evasion features as a pluggable extension
// to the dnstt DNSPacketConn. It implements base36 encoding, variable-length
// labels, CDN prefix camouflage, query jitter, and cover traffic.
package client

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"time"

	"www.bamsoftware.com/git/dnstt.git/dns"
	dnsttclient "www.bamsoftware.com/git/dnstt.git/dnstt-client/lib"
	"www.bamsoftware.com/git/dnstt.git/turbotunnel"
)

// noizLabelMin and noizLabelMax define the range for variable-length labels.
// Varying between 28-42 chars avoids the fixed-length pattern that DPI can
// fingerprint. The labels look like CDN cache keys or analytics tracking IDs.
// Using 28 min (vs 20) significantly improves payload capacity while still
// providing enough variation to avoid fixed-length fingerprinting.
const (
	noizLabelMin = 28
	noizLabelMax = 42
)


// DefaultJitterMax is the default maximum random delay added before each send.
// Set to 0 to maximize throughput; DNS tunnels are too bandwidth-constrained
// for jitter to be worth the latency cost.
const DefaultJitterMax = 0

// rrTypeHTTPS is the SVCB/HTTPS DNS record type (65).
// Chrome sends these since ~2022 for HTTPS-capable domains.
const rrTypeHTTPS = 65

// QueryPadding enables random EDNS0 padding (RFC 7830) on every tunnel query,
// adding 0–QueryPaddingMax random bytes to vary the wire size. Use together
// with --query-size to keep queries small AND randomly sized.
// No server changes required; the server ignores EDNS0 padding.
var QueryPadding = false

// QueryPaddingMax is the maximum number of random padding bytes added per
// query when QueryPadding is enabled. Default 20 gives a 20-byte size window.
var QueryPaddingMax = 20

// DefaultCoverDomains are real domains queried as cover traffic.
// Mixes international platform domains (Android/iOS background traffic)
// with domestic domains reachable during internet shutdowns.
var DefaultCoverDomains = []string{
	// Android/iOS background traffic
	"connectivitycheck.gstatic.com",
	"clients3.google.com",
	"play.googleapis.com",
	"mtalk.google.com",
	"captive.apple.com",
	"push.apple.com",
	"graph.facebook.com",
	"gateway.icloud.com",
	"firebaseinstallations.googleapis.com",
	"ocsp.digicert.com",
	// Domestic (reachable during shutdowns)
	"digikala.com",
	"aparat.com",
	"divar.ir",
	"snapp.ir",
	"shaparak.ir",
	"bale.ai",
	"rubika.ir",
	"namnak.com",
	"tamin.ir",
}

// chromeInfraDomains are domains Chrome queries on startup and periodically
// (Safe Browsing, updates, sync, predictor). Used for background activity.
var chromeInfraDomains = []string{
	"clients1.google.com",
	"clients2.google.com",
	"update.googleapis.com",
	"safebrowsing.googleapis.com",
	"accounts.google.com",
	"ssl.gstatic.com",
	"fonts.googleapis.com",
	"www.gstatic.com",
	"translate.googleapis.com",
}

// backgroundDomains are CDN/analytics domains Chrome resolves in the background.
var backgroundDomains = []string{
	"www.googletagmanager.com",
	"www.google-analytics.com",
	"pagead2.googlesyndication.com",
	"ocsp.digicert.com",
	"ocsp.pki.goog",
	"crl.pki.goog",
	"cloudflareinsights.com",
	"cdn.jsdelivr.net",
	"cdnjs.cloudflare.com",
}

// chineseOemInterceptedDomains are domains that Chinese OEM ROMs (MIUI,
// HyperOS, EMUI) intercept or override DNS responses for.
var chineseOemInterceptedDomains = map[string]bool{
	"connectivitycheck.gstatic.com":        true,
	"clients3.google.com":                  true,
	"play.googleapis.com":                  true,
	"mtalk.google.com":                     true,
	"firebaseinstallations.googleapis.com": true,
	// Chrome infra domains intercepted by Chinese OEM ROMs
	"clients1.google.com":         true,
	"clients2.google.com":         true,
	"update.googleapis.com":       true,
	"accounts.google.com":         true,
	"translate.googleapis.com":    true,
	"www.google-analytics.com":    true,
	"pagead2.googlesyndication.com": true,
}

// chineseOemManufacturers maps lowercase manufacturer names to true.
var chineseOemManufacturers = map[string]bool{
	"xiaomi": true, "redmi": true, "poco": true,
	"huawei": true, "honor": true,
	"oppo": true, "vivo": true, "realme": true, "oneplus": true,
	"meizu": true, "zte": true, "lenovo": true,
}

// filterCoverDomains removes intercepted domains for Chinese OEM devices.
func filterCoverDomains(domains []string, manufacturer string) []string {
	mfr := strings.ToLower(strings.TrimSpace(manufacturer))
	if mfr == "" || !chineseOemManufacturers[mfr] {
		return domains
	}
	var filtered []string
	for _, d := range domains {
		if !chineseOemInterceptedDomains[d] {
			filtered = append(filtered, d)
		}
	}
	return filtered
}

// noizCDNPrefixes are multi-level fake labels prepended to queries to make the
// domain name look like a real CDN or cloud endpoint. Every label MUST contain
// a hyphen so the server can distinguish them from base36 data labels.
// In stealth mode ALL queries get a prefix; normal mode uses ~25%.
var noizCDNPrefixes = [][]string{
	{"img-cache", "us-east-1"},
	{"cdn-static", "prod-v1"},
	{"api-gw", "eu-west-2"},
	{"assets-cdn", "v3-rel"},
	{"static-cdn", "origin-gw"},
	{"media-cdn", "global-r1"},
	{"js-pkg", "release-v2"},
	{"wss-proxy", "region-1"},
	{"content-cdn", "dist-v1"},
	{"app-static", "v2-rel"},
	{"logs-v1", "ingest-gw"},
	{"tele-metric", "collect-v1"},
	{"img-opt", "cdn-r2"},
	{"style-min", "css-v1"},
	{"font-woff", "cdn-r3"},
}

// variableChunks splits p into labels of random lengths between min and max.
// This avoids the fixed-length label pattern of regular dnstt.
func variableChunks(p []byte, min, max int) [][]byte {
	var result [][]byte
	for len(p) > 0 {
		sz := min
		if max > min {
			var b [1]byte
			_, _ = rand.Read(b[:])
			sz = min + int(b[0])%(max-min+1)
		}
		if sz > len(p) {
			sz = len(p)
		}
		result = append(result, p[:sz])
		p = p[sz:]
	}
	return result
}

// base36Encode encodes binary data as a base36 string (0-9, a-z).
// A 0x01 marker byte is prepended to preserve leading zeros.
func base36Encode(data []byte) string {
	if len(data) == 0 {
		return "0"
	}
	padded := make([]byte, len(data)+1)
	padded[0] = 0x01
	copy(padded[1:], data)
	return new(big.Int).SetBytes(padded).Text(36)
}

// makeSendFunc creates a SendFunc that uses NoizDNS base36 encoding with
// variable-length labels and CDN prefix camouflage.
// If cdnAlways is true, every query gets a CDN prefix (stealth mode).
func makeSendFunc(clientID turbotunnel.ClientID, domain dns.Name, cdnAlways bool) dnsttclient.SendFunc {
	return func(transport net.PacketConn, p []byte, addr net.Addr) error {
		var decoded []byte
		{
			if len(p) >= 224 {
				return fmt.Errorf("too long")
			}
			var buf bytes.Buffer
			// ClientID
			buf.Write(clientID[:])
			// NoizDNS uses the same padding count for data and polls.
			// Variable-length labels already provide cache uniqueness,
			// so the extra 8-byte poll padding from upstream dnstt is
			// unnecessary and wastes 10 hex chars of label space.
			n := dnsttclient.NumPadding
			// Padding / cache inhibition
			buf.WriteByte(byte(224 + n))
			_, _ = io.CopyN(&buf, rand.Reader, int64(n))
			// Packet contents
			if len(p) > 0 {
				buf.WriteByte(byte(len(p)))
				buf.Write(p)
			}
			decoded = buf.Bytes()
		}

		// Base36 encode (0-9, a-z) — looks like CDN cache keys.
		encoded := []byte(base36Encode(decoded))
		labels := variableChunks(encoded, noizLabelMin, noizLabelMax)

		// CDN-like prefix labels for camouflage.
		// cdnAlways=true (stealth): 100% of queries get a prefix.
		// cdnAlways=false (normal): ~25% of queries get a prefix.
		addPrefix := cdnAlways
		if !addPrefix {
			var rb [1]byte
			_, _ = rand.Read(rb[:])
			addPrefix = rb[0]&3 == 0
		}
		if addPrefix {
			idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(noizCDNPrefixes))))
			prefix := noizCDNPrefixes[idx.Int64()]
			prefixLabels := make([][]byte, len(prefix))
			for i, p := range prefix {
				prefixLabels[i] = []byte(p)
			}
			labels = append(prefixLabels, labels...)
		}

		labels = append(labels, domain...)
		name, err := dns.NewName(labels)
		if err != nil {
			return err
		}

		var id uint16
		_ = binary.Read(rand.Reader, binary.BigEndian, &id)
		query := &dns.Message{
			ID:    id,
			Flags: 0x0120, // QR=0, RD=1, AD=1 (mimic Chrome since ~2020)
			Question: []dns.Question{
				{
					Name:  name,
					Type:  dns.RRTypeTXT,
					Class: dns.ClassIN,
				},
			},
		}
		query.Additional = []dns.RR{
			{
				Name:  dns.Name{},
				Type:  dns.RRTypeOPT,
				Class: 1452, // EDNS0 UDP payload size — matches Chrome
				TTL:   0,
				Data:  []byte{},
			},
		}
		buf, err := query.WireFormat()
		if err != nil {
			return err
		}

		if QueryPadding && QueryPaddingMax > 0 {
			buf = addEDNS0Padding(buf, randInt(QueryPaddingMax+1))
		}

		_, err = transport.WriteTo(buf, addr)
		return err
	}
}

// addEDNS0Padding appends an EDNS0 Padding option (RFC 7830, option code 12)
// with padLen zero bytes to the OPT record at the end of a DNS wire message.
// The OPT record must be the last record with empty RDATA (as built above).
func addEDNS0Padding(buf []byte, padLen int) []byte {
	if padLen <= 0 {
		return buf
	}
	// OPT RDATA sits at end of message. For empty Data, RDLENGTH is the
	// last 2 bytes of the current buffer. Update it to include the new option.
	rdLenOffset := len(buf) - 2
	old := binary.BigEndian.Uint16(buf[rdLenOffset : rdLenOffset+2])
	binary.BigEndian.PutUint16(buf[rdLenOffset:rdLenOffset+2], old+uint16(4+padLen))
	// Append option: code=12, length=padLen, then padLen zero bytes.
	opt := make([]byte, 4+padLen)
	binary.BigEndian.PutUint16(opt[0:2], 12)
	binary.BigEndian.PutUint16(opt[2:4], uint16(padLen))
	return append(buf, opt...)
}

// makeJitterHook returns a PreSendHook that adds random jitter between
// jitterMin and jitterMax before each send.
func makeJitterHook(jitterMin, jitterMax time.Duration) func() {
	spread := jitterMax - jitterMin
	return func() {
		if spread <= 0 {
			return
		}
		var jb [2]byte
		_, _ = rand.Read(jb[:])
		jitter := jitterMin + time.Duration(int(binary.BigEndian.Uint16(jb[:])) % int(spread/time.Millisecond)) * time.Millisecond
		time.Sleep(jitter)
	}
}

// randInt returns a random int in [0, n) using crypto/rand.
func randInt(n int) int {
	if n <= 0 {
		return 0
	}
	v, _ := rand.Int(rand.Reader, big.NewInt(int64(n)))
	return int(v.Int64())
}

// randBool returns true with the given probability [0.0, 1.0].
func randBool(prob float64) bool {
	var b [1]byte
	_, _ = rand.Read(b[:])
	return float64(b[0])/256.0 < prob
}

// pickRandom returns a random element from the slice.
func pickRandom(s []string) string {
	return s[randInt(len(s))]
}

// sleepRandMs sleeps for a random duration between minMs and maxMs milliseconds.
func sleepRandMs(minMs, maxMs int) {
	ms := minMs
	if maxMs > minMs {
		ms += randInt(maxMs - minMs)
	}
	if ms > 0 {
		time.Sleep(time.Duration(ms) * time.Millisecond)
	}
}

// sendCoverQuery sends a single cover DNS query with Chrome-like flags.
// Best-effort; errors are silently ignored.
func sendCoverQuery(transport net.PacketConn, addr net.Addr, domain string, qtype uint16) {
	name, err := dns.ParseName(domain)
	if err != nil {
		return
	}
	var id uint16
	_ = binary.Read(rand.Reader, binary.BigEndian, &id)
	query := &dns.Message{
		ID:    id,
		Flags: 0x0120, // QR=0, RD=1, AD=1 (Chrome since ~2020)
		Question: []dns.Question{
			{Name: name, Type: qtype, Class: dns.ClassIN},
		},
		Additional: []dns.RR{
			{
				Name:  dns.Name{},
				Type:  dns.RRTypeOPT,
				Class: 1452, // EDNS0 UDP payload size — matches Chrome
				TTL:   0,
				Data:  []byte{},
			},
		},
	}
	buf, err := query.WireFormat()
	if err != nil {
		return
	}
	_, _ = transport.WriteTo(buf, addr)
}

// simulatePageLoad sends a burst of cover queries mimicking a Chrome page load.
// Chrome resolves all resources for a page in a rapid burst: primary domain
// (A + AAAA + sometimes HTTPS), then 3-10 sub-resource lookups for CDNs,
// analytics, fonts, etc. The burst completes in 100-500ms, then silence.
func simulatePageLoad(coverDomains, bgDomains, chromeDomains []string, transport net.PacketConn, addr net.Addr) {
	primary := pickRandom(coverDomains)

	// Chrome always sends A + AAAA for the primary domain
	sendCoverQuery(transport, addr, primary, dns.RRTypeA)
	sleepRandMs(1, 10)
	sendCoverQuery(transport, addr, primary, dns.RRTypeAAAA)

	// Chrome sometimes sends HTTPS (type 65) since ~2022
	if randBool(0.6) {
		sleepRandMs(1, 5)
		sendCoverQuery(transport, addr, primary, rrTypeHTTPS)
	}

	// Sub-resource lookups (CDNs, analytics, fonts, etc.)
	subCount := 3 + randInt(8)
	for i := 0; i < subCount; i++ {
		sleepRandMs(10, 120)

		// Pick from different pools like a real page load
		var domain string
		r := randInt(10)
		switch {
		case r < 5: // 50% browsing domains
			domain = pickRandom(coverDomains)
		case r < 8: // 30% background/CDN domains
			domain = pickRandom(bgDomains)
		default: // 20% Chrome infra
			domain = pickRandom(chromeDomains)
		}

		sendCoverQuery(transport, addr, domain, dns.RRTypeA)

		// Chrome sends A + AAAA together ~80% of the time
		if randBool(0.8) {
			sleepRandMs(0, 5)
			sendCoverQuery(transport, addr, domain, dns.RRTypeAAAA)
		}
	}
}

// simulateChromeBackground sends 1-3 Chrome infra queries (Safe Browsing,
// update checks, predictor pre-resolve) with 50-500ms spacing.
func simulateChromeBackground(chromeDomains []string, transport net.PacketConn, addr net.Addr) {
	count := 1 + randInt(3)
	for i := 0; i < count; i++ {
		domain := pickRandom(chromeDomains)
		sendCoverQuery(transport, addr, domain, dns.RRTypeA)
		sleepRandMs(50, 500)
	}
}

// coverTrafficLoop sends cover DNS queries in page-load bursts to mimic real
// Chrome browsing. Instead of steady single queries, it sends 5-15 queries
// in rapid succession (100-500ms), then goes silent for several seconds —
// matching the burst pattern of actual page loads.
//
// Between bursts, occasional Chrome background queries (Safe Browsing,
// update checks) are injected for additional realism.
//
// pageLoadInterval controls the average seconds between page-load bursts.
// bgInterval controls the average seconds between background queries.
func coverTrafficLoop(coverDomains, bgDomains, chromeDomains []string, transport net.PacketConn, addr net.Addr, pageLoadInterval, bgInterval time.Duration) {
	// Chrome startup burst: resolve infra domains on "launch"
	count := 3 + randInt(3)
	for i := 0; i < count; i++ {
		domain := pickRandom(chromeDomains)
		sendCoverQuery(transport, addr, domain, dns.RRTypeA)
		sleepRandMs(5, 30)
	}

	pageLoadSecs := int(pageLoadInterval / time.Second)
	if pageLoadSecs < 3 {
		pageLoadSecs = 3
	}
	bgSecs := int(bgInterval / time.Second)
	if bgSecs < 5 {
		bgSecs = 5
	}

	for {
		// Simulate a page-load burst
		simulatePageLoad(coverDomains, bgDomains, chromeDomains, transport, addr)

		// Inter-burst silence with jitter (0.5x - 2.0x of base interval)
		var jb [1]byte
		_, _ = rand.Read(jb[:])
		jitter := 0.5 + float64(jb[0])/170.0 // ~[0.5, 2.0]
		waitSecs := int(float64(pageLoadSecs) * jitter)
		if waitSecs < 3 {
			waitSecs = 3
		}
		if waitSecs > 90 {
			waitSecs = 90
		}

		// During the silence, occasionally fire Chrome background queries
		elapsed := 0
		for elapsed < waitSecs {
			chunk := 3 + randInt(bgSecs-2)
			if chunk > waitSecs-elapsed {
				chunk = waitSecs - elapsed
			}
			time.Sleep(time.Duration(chunk) * time.Second)
			elapsed += chunk

			// ~30% chance of background activity per chunk
			if randBool(0.3) {
				simulateChromeBackground(chromeDomains, transport, addr)
			}
		}
	}
}

// DnsNameCapacityNoiz returns the number of payload bytes available when using
// NoizDNS base36 encoding with variable-length labels for the given domain.
// Uses worst-case assumptions (minimum label length, CDN prefix present) to
// ensure the send function never produces a name that exceeds 255 bytes.
func DnsNameCapacityNoiz(domain dns.Name) int {
	// Total DNS name capacity is 255 bytes.
	// Each label costs len(label) + 1 (length prefix).
	// Final null label costs 1 byte.
	capacity := 255
	capacity -= 1 // null terminator
	for _, label := range domain {
		capacity -= len(label) + 1
	}
	// Reserve space for CDN prefix labels (worst case: "img-cache" + "us-east-1" = 9+1+9+1 = 20 bytes).
	capacity -= 20
	// Each data label of noizLabelMin chars costs noizLabelMin + 1 bytes.
	numLabels := capacity / (noizLabelMin + 1)
	b36Chars := numLabels * noizLabelMin
	// Base36: ~5.17 bits per char. Conservative estimate: 5 bits per char.
	// Subtract 1 for the 0x01 marker byte used in base36Encode.
	return (b36Chars * 5 / 8) - 1
}

// NewNoizDNSPacketConn creates a new DNSPacketConn with NoizDNS evasion
// features enabled: hex encoding, variable-length labels, CDN prefix
// camouflage, and cover traffic. Stealth mode is off.
// deviceManufacturer filters cover domains that Chinese OEM ROMs intercept.
func NewNoizDNSPacketConn(transport net.PacketConn, addr net.Addr, domain dns.Name, config *dnsttclient.DNSPacketConnConfig, deviceManufacturer string) *dnsttclient.DNSPacketConn {
	return newNoizConn(transport, addr, domain, config, false, deviceManufacturer)
}

// NewNoizDNSPacketConnStealth creates a NoizDNS DNSPacketConn with stealth
// mode enabled: 100% CDN prefix on all queries, aggressive cover traffic
// (3-8s interval instead of 5-15s), and slower KCP polling.
// Reduces throughput but makes traffic much harder for DPI to fingerprint.
// deviceManufacturer filters cover domains that Chinese OEM ROMs intercept.
func NewNoizDNSPacketConnStealth(transport net.PacketConn, addr net.Addr, domain dns.Name, config *dnsttclient.DNSPacketConnConfig, deviceManufacturer string) *dnsttclient.DNSPacketConn {
	return newNoizConn(transport, addr, domain, config, true, deviceManufacturer)
}

func newNoizConn(transport net.PacketConn, addr net.Addr, domain dns.Name, config *dnsttclient.DNSPacketConnConfig, stealth bool, deviceManufacturer string) *dnsttclient.DNSPacketConn {
	clientID := turbotunnel.NewClientID()
	coverDomains := filterCoverDomains(DefaultCoverDomains, deviceManufacturer)
	filteredChrome := filterCoverDomains(chromeInfraDomains, deviceManufacturer)
	filteredBackground := filterCoverDomains(backgroundDomains, deviceManufacturer)

	hooks := &dnsttclient.DNSPacketConnHooks{
		CustomSendFunc: makeSendFunc(clientID, domain, stealth),
		ClientID:       &clientID,
	}

	// Jitter is intentionally NOT used even in stealth mode.
	// It delays every send including KCP ACKs and retransmits,
	// causing handshake timeouts. Cover traffic + slower polling
	// provide DPI resistance without breaking KCP timing.
	if DefaultJitterMax > 0 {
		hooks.PreSendHook = makeJitterHook(0, DefaultJitterMax)
	}

	// Cover traffic: always enabled with Chrome page-load burst pattern.
	// Stealth: faster burst cadence (5s page loads, 10s background).
	// Normal: relaxed cadence (15s page loads, 45s background).
	if len(coverDomains) > 0 {
		pageLoadInterval := 15 * time.Second
		bgInterval := 45 * time.Second
		if stealth {
			pageLoadInterval = 5 * time.Second
			bgInterval = 10 * time.Second
		}
		hooks.OnStart = func(transport net.PacketConn, addr net.Addr) {
			go coverTrafficLoop(coverDomains, filteredBackground, filteredChrome, transport, addr, pageLoadInterval, bgInterval)
		}
	}

	return dnsttclient.NewDNSPacketConnWithHooks(transport, addr, domain, config, hooks)
}
