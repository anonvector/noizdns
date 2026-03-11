// Package server provides the NoizDNS server-side decoding hooks.
// It plugs into the dnstt server library to add base36/hex encoding
// auto-detection and CDN prefix stripping.
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

// containsHyphen returns true if b contains a '-' character.
func containsHyphen(b []byte) bool {
	for _, c := range b {
		if c == '-' {
			return true
		}
	}
	return false
}

// isAllHex returns true if every byte in b is a valid lowercase hex character.
func isAllHex(b []byte) bool {
	for _, c := range b {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return len(b) > 0
}

// isAllAlphaNum returns true if every byte is [0-9a-z].
func isAllAlphaNum(b []byte) bool {
	for _, c := range b {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z')) {
			return false
		}
	}
	return len(b) > 0
}

// hasNonHexAlpha returns true if any byte is in [g-z].
func hasNonHexAlpha(b []byte) bool {
	for _, c := range b {
		if c >= 'g' && c <= 'z' {
			return true
		}
	}
	return false
}

// hasHexIndicator returns true if the data contains any of {0,1,8,9}
// which never appear in base32 (a-z, 2-7).
func hasHexIndicator(b []byte) bool {
	for _, c := range b {
		if c == '0' || c == '1' || c == '8' || c == '9' {
			return true
		}
	}
	return false
}

// base36Decode decodes a base36 string back to binary.
// Expects a 0x01 marker byte prefix (added by the encoder to preserve leading zeros).
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

// decodePayload auto-detects the encoding used in DNS subdomain labels:
//
//   - base36 (NoizDNS v2): labels [0-9a-z], CDN prefixes have hyphens
//   - hex    (NoizDNS v1): labels [0-9a-f], CDN prefixes are short non-hex words
//   - base32 (dnstt):      labels [a-z2-7], no CDN prefixes
//
// Detection order:
//  1. Skip hyphenated labels (new CDN prefixes)
//  2. From remaining, extract hex-only labels → try hex decode
//  3. If hex fails and data has [g-z] + [0189] → try base36
//  4. Fallback → base32
func decodePayload(prefix dns.Name) ([]byte, error) {
	// Step 1: Filter out labels with hyphens (new-style CDN prefixes).
	var noHyphenLabels [][]byte
	for _, label := range prefix {
		lbl := bytes.ToLower(label)
		if !containsHyphen(lbl) && len(lbl) > 0 {
			noHyphenLabels = append(noHyphenLabels, lbl)
		}
	}

	// Step 2: Try hex — filter out non-hex labels (old CDN prefixes like "cdn", "img").
	var hexLabels [][]byte
	for _, lbl := range noHyphenLabels {
		if isAllHex(lbl) {
			hexLabels = append(hexLabels, lbl)
		}
	}
	if len(hexLabels) > 0 {
		hexJoined := bytes.Join(hexLabels, nil)
		if hasHexIndicator(hexJoined) {
			payload, err := hex.DecodeString(string(hexJoined))
			if err == nil {
				return payload, nil
			}
		}
	}

	// Step 3: Try base36 — requires both [g-z] AND [0189] to distinguish from base32.
	// base32 uses [a-z2-7] so it never has [0189]. base36 almost always does.
	if len(noHyphenLabels) > 0 {
		// Only include alphanumeric labels (skip any remaining garbage).
		var alphaNumLabels [][]byte
		for _, lbl := range noHyphenLabels {
			if isAllAlphaNum(lbl) {
				alphaNumLabels = append(alphaNumLabels, lbl)
			}
		}
		if len(alphaNumLabels) > 0 {
			joined := bytes.Join(alphaNumLabels, nil)
			if hasNonHexAlpha(joined) && hasHexIndicator(joined) {
				payload, err := base36Decode(string(joined))
				if err == nil {
					return payload, nil
				}
			}
		}
	}

	// Step 4: base32 fallback (standard dnstt).
	encoded := bytes.ToUpper(bytes.Join(prefix, nil))
	payload := make([]byte, base32Encoding.DecodedLen(len(encoded)))
	n, err := base32Encoding.Decode(payload, encoded)
	if err != nil {
		return nil, fmt.Errorf("base32 decoding: %v", err)
	}
	return payload[:n], nil
}

// NewHooks returns ServerHooks that enable NoizDNS decoding on the dnstt server.
// Only DecodePayload is overridden; AcceptQueryType defaults to TXT.
func NewHooks() *serverlib.ServerHooks {
	return &serverlib.ServerHooks{
		DecodePayload: decodePayload,
	}
}
