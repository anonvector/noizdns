// Package client provides stealth encoding and cover traffic for NoizDNS tunnels.
//
// StealthSender replaces the default dnstt send() with variable-length label
// splitting and per-query random padding. This breaks the fixed 63-byte label
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
	// Varying between 15-40 chars avoids the fixed 63-char pattern that
	// DPI fingerprints. The labels look like CDN cache keys or analytics IDs.
	stealthLabelMin = 15
	stealthLabelMax = 40

	// stealthPollPadding is the padding for empty poll queries (cache busting).
	stealthPollPadding = 8
)

// StealthSender encodes DNS tunnel packets with variable-length labels
// and random padding. It implements the dnstt CustomSendFunc interface.
type StealthSender struct {
	ClientID  turbotunnel.ClientID
	Domain    dns.Name
	EDNS0Size int
}

// Send encodes p into a DNS query with variable-length labels and sends it.
// This is a drop-in replacement for dnstt's default send() function.
func (s *StealthSender) Send(transport net.PacketConn, p []byte, addr net.Addr) error {
	if len(p) >= 224 {
		return fmt.Errorf("too long")
	}

	// Build the raw payload: ClientID + padding header + random padding + data.
	var buf bytes.Buffer
	buf.Write(s.ClientID[:])

	var padLen int
	if len(p) == 0 {
		// Poll query: fixed padding for cache busting.
		padLen = stealthPollPadding
	}
	// Data queries: no extra padding needed — variable-length labels
	// already vary the QNAME length per query.
	buf.WriteByte(byte(224 + padLen))
	_, _ = io.CopyN(&buf, rand.Reader, int64(padLen))

	if len(p) > 0 {
		buf.WriteByte(byte(len(p)))
		buf.Write(p)
	}

	// Base32 encode.
	decoded := buf.Bytes()
	encoded := make([]byte, stealthBase32.EncodedLen(len(decoded)))
	stealthBase32.Encode(encoded, decoded)
	encoded = bytes.ToLower(encoded)

	// Split into variable-length labels instead of fixed 63-byte chunks.
	labels := varChunks(encoded, stealthLabelMin, stealthLabelMax)
	labels = append(labels, s.Domain...)
	name, err := dns.NewName(labels)
	if err != nil {
		return err
	}

	// Build DNS query.
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
		Additional: []dns.RR{
			{
				Name:  dns.Name{},
				Type:  dns.RRTypeOPT,
				Class: s.edns0Class(),
				TTL:   0,
				Data:  []byte{},
			},
		},
	}
	wire, err := query.WireFormat()
	if err != nil {
		return err
	}

	_, err = transport.WriteTo(wire, addr)
	return err
}

func (s *StealthSender) edns0Class() uint16 {
	if s.EDNS0Size > 0 {
		return uint16(s.EDNS0Size)
	}
	return 1232 // RFC 8020 default for stealth
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
