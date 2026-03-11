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

// DefaultCoverDomains are real domains queried as cover traffic.
// DefaultCoverDomains mixes international platform domains (Android/iOS
// background traffic) with domestic domains that remain reachable during
// internet shutdowns. This ensures cover traffic looks natural in both
// normal conditions and restricted network states.
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
			Flags: 0x0100, // QR = 0, RD = 1
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
				Class: 1232,
				TTL:   0,
				Data:  []byte{},
			},
		}
		buf, err := query.WireFormat()
		if err != nil {
			return err
		}

		_, err = transport.WriteTo(buf, addr)
		return err
	}
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

// coverTrafficLoop sends periodic legitimate DNS queries to real domains to
// dilute the tunnel-to-total DNS ratio. minInterval/maxInterval control timing;
// stealth mode uses shorter intervals for a higher cover-to-tunnel ratio.
func coverTrafficLoop(coverDomains []string, transport net.PacketConn, addr net.Addr, minInterval, maxInterval time.Duration) {
	spread := int((maxInterval - minInterval) / time.Second)
	if spread <= 0 {
		spread = 1
	}
	for {
		var b [1]byte
		_, _ = rand.Read(b[:])
		delay := minInterval + time.Duration(int(b[0])%spread)*time.Second
		time.Sleep(delay)

		// Pick a random cover domain.
		idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(coverDomains))))
		coverDomain := coverDomains[idx.Int64()]

		name, err := dns.ParseName(coverDomain)
		if err != nil {
			continue
		}

		var id uint16
		_ = binary.Read(rand.Reader, binary.BigEndian, &id)
		query := &dns.Message{
			ID:    id,
			Flags: 0x0100, // QR = 0, RD = 1
			Question: []dns.Question{
				{
					Name:  name,
					Type:  dns.RRTypeA,
					Class: dns.ClassIN,
				},
			},
		}
		buf, err := query.WireFormat()
		if err != nil {
			continue
		}
		// Best-effort; ignore errors. recvLoop will silently discard
		// responses that don't match our tunnel domain.
		_, _ = transport.WriteTo(buf, addr)
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
func NewNoizDNSPacketConn(transport net.PacketConn, addr net.Addr, domain dns.Name, config *dnsttclient.DNSPacketConnConfig) *dnsttclient.DNSPacketConn {
	return newNoizConn(transport, addr, domain, config, false)
}

// NewNoizDNSPacketConnStealth creates a NoizDNS DNSPacketConn with stealth
// mode enabled: 100% CDN prefix on all queries, aggressive cover traffic
// (3-8s interval instead of 5-15s), and slower KCP polling.
// Reduces throughput but makes traffic much harder for DPI to fingerprint.
func NewNoizDNSPacketConnStealth(transport net.PacketConn, addr net.Addr, domain dns.Name, config *dnsttclient.DNSPacketConnConfig) *dnsttclient.DNSPacketConn {
	return newNoizConn(transport, addr, domain, config, true)
}

func newNoizConn(transport net.PacketConn, addr net.Addr, domain dns.Name, config *dnsttclient.DNSPacketConnConfig, stealth bool) *dnsttclient.DNSPacketConn {
	clientID := turbotunnel.NewClientID()
	coverDomains := DefaultCoverDomains

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

	// Cover traffic: always enabled.
	// Stealth: 3-8s cover traffic interval (more frequent than normal).
	// Normal: relaxed 5-15s interval.
	if len(coverDomains) > 0 {
		minInterval := 5 * time.Second
		maxInterval := 15 * time.Second
		if stealth {
			minInterval = 3 * time.Second
			maxInterval = 8 * time.Second
		}
		hooks.OnStart = func(transport net.PacketConn, addr net.Addr) {
			go coverTrafficLoop(coverDomains, transport, addr, minInterval, maxInterval)
		}
	}

	return dnsttclient.NewDNSPacketConnWithHooks(transport, addr, domain, config, hooks)
}
