// Package client provides cover traffic for NoizDNS tunnels.
//
// Cover traffic sends periodic legitimate DNS queries to real domains through
// the same DoH/DoT transport as the tunnel, diluting the traffic analysis
// signal that DPI uses to identify tunnel-only resolver usage.
package client

import (
	"crypto/rand"
	"encoding/binary"
	"math/big"
	"net"
	"strings"
	"time"

	"www.bamsoftware.com/git/dnstt.git/dns"
)

// DefaultCoverDomains are real domains queried as cover traffic.
// Mixes international platform domains (Android/iOS background traffic) with
// domestic domains that remain reachable during internet shutdowns.
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

// chineseOemInterceptedDomains are domains that Chinese OEM ROMs (MIUI,
// HyperOS, EMUI) intercept or override DNS responses for.
var chineseOemInterceptedDomains = map[string]bool{
	"connectivitycheck.gstatic.com":        true,
	"clients3.google.com":                  true,
	"play.googleapis.com":                  true,
	"mtalk.google.com":                     true,
	"firebaseinstallations.googleapis.com": true,
}

// chineseOemManufacturers maps lowercase manufacturer names to true.
var chineseOemManufacturers = map[string]bool{
	"xiaomi": true, "redmi": true, "poco": true,
	"huawei": true, "honor": true,
	"oppo": true, "vivo": true, "realme": true, "oneplus": true,
	"meizu": true, "zte": true, "lenovo": true,
}

// FilterCoverDomains removes intercepted domains for Chinese OEM devices.
func FilterCoverDomains(domains []string, manufacturer string) []string {
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

// CoverTrafficLoop sends periodic legitimate DNS queries to real domains to
// dilute the tunnel-to-total DNS ratio. minInterval/maxInterval control timing.
// Returns when the transport is closed.
func CoverTrafficLoop(coverDomains []string, transport net.PacketConn, addr net.Addr, minInterval, maxInterval time.Duration) {
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
		// Exit if the transport was closed (tunnel stopped).
		if _, err := transport.WriteTo(buf, addr); err != nil {
			return
		}
	}
}
