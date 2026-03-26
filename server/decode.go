// Package server provides backward-compatible decoding hooks for the NoizDNS
// server. It auto-detects base32 (current), base36, and hex encodings so the
// server can accept both new and old clients.
package server

import (
	"bytes"
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"math/big"

	"www.bamsoftware.com/git/dnstt.git/dns"
	serverlib "www.bamsoftware.com/git/dnstt.git/dnstt-server/lib"
)

var base32Encoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// decodePayload auto-detects the encoding used in DNS subdomain labels.
//
// Fast path (new clients — base32): labels contain only [a-z2-7]. A single
// pass detects this and decodes immediately — no intermediate allocations.
//
// Legacy path (old clients — hex or base36): labels contain {0,1,8,9} or
// hyphens (CDN prefixes). Falls through to hex → base36 → base32 detection.
func decodePayload(prefix dns.Name) ([]byte, error) {
	// Single pass: check if any label contains characters that cannot
	// appear in base32 ([a-z2-7]). {0,1,8,9} and hyphens indicate
	// legacy hex/base36 encoding with possible CDN prefixes.
	legacy := false
	for _, label := range prefix {
		for _, c := range label {
			if c == '-' || c == '0' || c == '1' || c == '8' || c == '9' {
				legacy = true
				break
			}
		}
		if legacy {
			break
		}
	}

	// Fast path: standard base32 (all new clients).
	if !legacy {
		encoded := bytes.ToUpper(bytes.Join(prefix, nil))
		payload := make([]byte, base32Encoding.DecodedLen(len(encoded)))
		n, err := base32Encoding.Decode(payload, encoded)
		if err != nil {
			return nil, fmt.Errorf("base32 decoding: %v", err)
		}
		return payload[:n], nil
	}

	// Legacy path: strip CDN prefix labels (contain hyphens), then try
	// hex → base36 → base32 fallback. Only reached by old clients.
	return decodeLegacy(prefix)
}

// decodeLegacy handles old NoizDNS clients that use hex or base36 encoding
// with optional CDN prefix labels.
func decodeLegacy(prefix dns.Name) ([]byte, error) {
	// Filter labels: separate data labels from CDN prefix labels.
	// CDN prefixes contain hyphens; data labels are alphanumeric.
	var dataLabels [][]byte
	for _, label := range prefix {
		lbl := bytes.ToLower(label)
		if len(lbl) > 0 && bytes.IndexByte(lbl, '-') < 0 {
			dataLabels = append(dataLabels, lbl)
		}
	}

	if len(dataLabels) == 0 {
		return nil, fmt.Errorf("no data labels found")
	}

	joined := bytes.Join(dataLabels, nil)

	// Try hex: if all data bytes are [0-9a-f] and contain {0,1,8,9}.
	if isAllHex(joined) && hasHexIndicator(joined) {
		if payload, err := hex.DecodeString(string(joined)); err == nil {
			return payload, nil
		}
	}

	// Try base36: requires both [g-z] (not hex) and {0,1,8,9} (not base32).
	if hasNonHexAlpha(joined) && hasHexIndicator(joined) {
		if payload, err := base36Decode(string(joined)); err == nil {
			return payload, nil
		}
	}

	// Fallback: base32.
	encoded := bytes.ToUpper(bytes.Join(prefix, nil))
	payload := make([]byte, base32Encoding.DecodedLen(len(encoded)))
	n, err := base32Encoding.Decode(payload, encoded)
	if err != nil {
		return nil, fmt.Errorf("base32 decoding: %v", err)
	}
	return payload[:n], nil
}

func isAllHex(b []byte) bool {
	for _, c := range b {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return len(b) > 0
}

func hasNonHexAlpha(b []byte) bool {
	for _, c := range b {
		if c >= 'g' && c <= 'z' {
			return true
		}
	}
	return false
}

func hasHexIndicator(b []byte) bool {
	for _, c := range b {
		if c == '0' || c == '1' || c == '8' || c == '9' {
			return true
		}
	}
	return false
}

func base36Decode(s string) ([]byte, error) {
	n, ok := new(big.Int).SetString(s, 36)
	if !ok {
		return nil, fmt.Errorf("invalid base36 string")
	}
	b := n.Bytes()
	if len(b) == 0 || b[0] != 0x01 {
		return nil, fmt.Errorf("missing base36 marker byte")
	}
	return b[1:], nil
}

// NewHooks returns ServerHooks with backward-compatible decoding.
func NewHooks() *serverlib.ServerHooks {
	return &serverlib.ServerHooks{
		DecodePayload: decodePayload,
	}
}
