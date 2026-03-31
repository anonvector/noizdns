// Package client provides custom DNS tunnel encoding for NoizDNS.
//
// NormalSender and StealthSender replace the default dnstt send() to skip
// random padding and maximize payload capacity. StealthSender additionally
// uses variable-length label splitting to break the fixed 63-byte label
// fingerprint that DPI uses to identify dnstt tunnel traffic.
package client

import (
	"bytes"
	"crypto/rand"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"www.bamsoftware.com/git/dnstt.git/dns"
	"www.bamsoftware.com/git/dnstt.git/turbotunnel"
)

var stealthBase32 = base32.StdEncoding.WithPadding(base32.NoPadding)

const (
	// stealthLabelMin/Max define the range for variable-length labels.
	// Varying between 25-40 chars avoids the fixed 63-char pattern that
	// DPI fingerprints. The labels look like CDN cache keys or analytics IDs.
	stealthLabelMin = 25
	stealthLabelMax = 40
)

// cdnPrefixes are multi-level fake labels prepended to ~25% of queries to make
// the domain look like a real CDN or cloud endpoint. Every label contains a
// hyphen so the server can distinguish them from base32 data labels.
var cdnPrefixes = [][]string{
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

// maybeCDNPrefix prepends a random CDN prefix to labels with the given probability.
// rate=4 means ~25% (1 in 4), rate=1 means 100%.
func maybeCDNPrefix(labels dns.Name, rate int) dns.Name {
	var b [1]byte
	_, _ = rand.Read(b[:])
	if rate > 1 && int(b[0])%rate != 0 {
		return labels
	}
	idx := int(b[0]) % len(cdnPrefixes)
	prefix := cdnPrefixes[idx]
	prefixLabels := make(dns.Name, len(prefix))
	for i, p := range prefix {
		prefixLabels[i] = []byte(p)
	}
	return append(prefixLabels, labels...)
}

// NormalSender replaces the default dnstt send() with zero-padding encoding.
// Uses fixed 63-byte labels (same as dnstt) but skips random padding to
// maximize payload capacity. ~25% of queries get CDN prefix camouflage.
type NormalSender struct {
	ClientID  turbotunnel.ClientID
	Domain    dns.Name
	EDNS0Size int
}

// Send encodes p into a DNS query with fixed 63-byte labels and no padding.
func (s *NormalSender) Send(transport net.PacketConn, p []byte, addr net.Addr) error {
	encoded, err := encodePayload(s.ClientID, p)
	if err != nil {
		return err
	}
	labels := chunks(encoded, 63)
	labels = append(labels, s.Domain...)
	return sendQuery(labels, s.EDNS0Size, transport, addr)
}

// StealthSender encodes DNS tunnel packets with variable-length labels.
// It implements the dnstt CustomSendFunc interface.
type StealthSender struct {
	ClientID  turbotunnel.ClientID
	Domain    dns.Name
	EDNS0Size int
}

// Send encodes p into a DNS query with variable-length labels and sends it.
// All stealth queries get CDN prefix camouflage.
func (s *StealthSender) Send(transport net.PacketConn, p []byte, addr net.Addr) error {
	encoded, err := encodePayload(s.ClientID, p)
	if err != nil {
		return err
	}
	labels := varChunks(encoded, stealthLabelMin, stealthLabelMax)
	labels = maybeCDNPrefix(labels, 1) // 100% of queries
	labels = append(labels, s.Domain...)
	return sendQuery(labels, s.EDNS0Size, transport, addr)
}

// numPadding is the number of random bytes added to each query for cache busting.
// Without this, poll queries (no payload) produce identical QNAMEs and get cached
// by the resolver, stalling the tunnel.
const numPadding = 1

// encodePayload builds the base32-encoded QNAME payload with random padding.
func encodePayload(clientID turbotunnel.ClientID, p []byte) ([]byte, error) {
	if len(p) >= 224 {
		return nil, fmt.Errorf("payload too long: %d >= 224", len(p))
	}
	var buf bytes.Buffer
	buf.Write(clientID[:])
	buf.WriteByte(byte(224 + numPadding))
	_, _ = io.CopyN(&buf, rand.Reader, numPadding)
	if len(p) > 0 {
		buf.WriteByte(byte(len(p)))
		buf.Write(p)
	}
	decoded := buf.Bytes()
	encoded := make([]byte, stealthBase32.EncodedLen(len(decoded)))
	stealthBase32.Encode(encoded, decoded)
	return bytes.ToLower(encoded), nil
}

// sendQuery builds a DNS TXT query from pre-split labels and sends it.
func sendQuery(labels dns.Name, edns0Size int, transport net.PacketConn, addr net.Addr) error {
	name, err := dns.NewName(labels)
	if err != nil {
		return err
	}
	var id uint16
	_ = binary.Read(rand.Reader, binary.BigEndian, &id)
	ec := uint16(1232)
	if edns0Size > 0 {
		ec = uint16(edns0Size)
	}
	query := &dns.Message{
		ID:    id,
		Flags: 0x0100,
		Question: []dns.Question{
			{Name: name, Type: dns.RRTypeTXT, Class: dns.ClassIN},
		},
		Additional: []dns.RR{
			{Name: dns.Name{}, Type: dns.RRTypeOPT, Class: ec, TTL: 0, Data: []byte{}},
		},
	}
	wire, err := query.WireFormat()
	if err != nil {
		return err
	}
	_, err = transport.WriteTo(wire, addr)
	return err
}

// chunks splits p into fixed-size pieces of at most n bytes.
func chunks(p []byte, n int) [][]byte {
	var result [][]byte
	for len(p) > 0 {
		sz := n
		if sz > len(p) {
			sz = len(p)
		}
		result = append(result, p[:sz])
		p = p[sz:]
	}
	return result
}

// varChunks splits p into labels with random lengths between minLen and maxLen.
// The last label gets whatever remains. Server-side reassembly just concatenates
// all labels, so variable splitting is fully backward compatible.
func varChunks(p []byte, minLen, maxLen int) [][]byte {
	var result [][]byte
	spread := maxLen - minLen + 1
	for len(p) > 0 {
		// Random label length in [minLen, maxLen].
		var b [1]byte
		_, _ = rand.Read(b[:])
		n := minLen + int(b[0])%spread
		if n > len(p) {
			n = len(p)
		}
		// Don't leave a tiny remainder that would be a conspicuous short label.
		// If the remainder would be < minLen, absorb it into this label.
		if len(p)-n > 0 && len(p)-n < minLen {
			n = len(p)
		}
		// DNS label max is 63, clamp just in case.
		if n > 63 {
			n = 63
		}
		result = append(result, p[:n])
		p = p[n:]
	}
	return result
}

// StealthNameCapacity returns the binary payload capacity for stealth mode.
// Uses the minimum label size for conservative MTU calculation (guarantees
// the QNAME always fits within maxQNAMELen).
func StealthNameCapacity(domain dns.Name, maxQNAMELen int) int {
	capacity := maxQNAMELen
	capacity -= 1 // null terminator
	for _, label := range domain {
		capacity -= len(label) + 1
	}
	if capacity < 0 {
		return 0
	}
	// Variable labels: worst case is all labels at minimum size.
	// Each label of minLen bytes costs minLen+1 wire bytes.
	capacity = capacity * stealthLabelMin / (stealthLabelMin + 1)
	// Base32 expansion: 5 binary bytes → 8 encoded chars.
	capacity = capacity * 5 / 8
	return capacity
}
