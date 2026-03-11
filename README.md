# NoizDNS

DPI-evasion layer built on top of [dnstt](https://www.bamsoftware.com/software/dnstt/). Extends dnstt with advanced anti-censorship features to make DNS tunnel traffic harder to detect and block.

The server auto-detects base36 (NoizDNS v2), hex (NoizDNS v1), and base32 (standard dnstt) clients simultaneously through a single endpoint.

## Features

### Base36 Encoding
- Encodes data using full alphanumeric charset (0-9, a-z) instead of dnstt's base32 or hex
- Labels look like CDN cache keys or analytics tracking IDs
- ~29% more capacity than hex, ~3% more than base32

### Variable-Length Labels
- Splits encoded data into labels of random lengths (28-42 chars)
- Avoids fixed-length patterns that DPI can fingerprint
- Standard dnstt uses fixed 63-char labels

### CDN Prefix Camouflage
- Prepends realistic multi-level DNS labels to queries
- Makes tunnel queries look like real CDN/cloud endpoints
- 15 prefix patterns (e.g., `cdn-static.prod-v1`, `img-cache.us-east-1`, `wss-proxy.region-1`)
- All prefixes contain hyphens for reliable server-side filtering
- Normal mode: ~25% of queries get a prefix
- Stealth mode: 100% of queries

Example query:
```
img-cache.us-east-1.k7m2x9nq4wp5zt8rj3hv6bc.y1da0fu8l5onge.t.example.com
```

### Cover Traffic
- Sends periodic legitimate DNS A queries to real domains
- Dilutes tunnel-to-total DNS ratio for statistical evasion
- Normal: 5-15s intervals, Stealth: 3-8s intervals
- Default domains: connectivitycheck.gstatic.com, clients3.google.com, play.googleapis.com, mtalk.google.com, captive.apple.com, graph.facebook.com, api.whatsapp.com, push.apple.com, google.com, microsoft.com

### Stealth Mode
Trades throughput for maximum DPI resistance:
- 100% CDN prefix on all queries
- More frequent cover traffic (3-8s)
- Slower KCP polling (250ms init, 5s max)
- Moderate KCP windows (128x128)
- Max 16 concurrent streams

## Architecture

```
noizdns/
├── client/
│   └── noizdns.go          # Client-side: base36, variable labels, CDN prefix, cover traffic
├── server/
│   └── decode.go           # Server-side: auto-detection and decoding (base36/hex/base32)
├── mobile/
│   ├── mobile.go           # gomobile-compatible client API (Android/iOS)
│   └── multi.go            # Multi-resolver health tracking and round-robin
└── cmd/
    └── noizdns-server/
        └── main.go         # Pluggable transport server binary
```

## Server Auto-Detection

The server decodes any encoding automatically per-query:

```
Step 1: Skip labels with hyphens (CDN prefixes)
Step 2: Try hex decode on [0-9a-f] labels with [0189] indicators
Step 3: Try base36 on [0-9a-z] labels with both [g-z] AND [0189]
Step 4: Fallback to base32 (standard dnstt)
```

Why this works:
- **base32** uses [a-z2-7] — never has [0189]
- **hex** uses [0-9a-f] — never has [g-z]
- **base36** uses [0-9a-z] — almost always has both [g-z] AND [0189]
- **CDN prefixes** have hyphens — always filtered first

## Connection Modes

| Setting | Authoritative | Normal NoizDNS | Stealth | Standard dnstt |
|---|---|---|---|---|
| PollLimit | 16 | 12 | 10 | 8 |
| InitPollDelay | 200ms | 150ms | 250ms | default |
| MaxPollDelay | 4s | 4s | 5s | default |
| KCP Flush | 20ms | 30ms | 40ms | default |
| KCP Window | 256x256 | 192x192 | 128x128 | 64x64 |
| ACK NoDelay | yes | yes | no | no |
| Max Streams | unlimited | 20 | 16 | 32 |
| CDN Prefix | N/A | 25% | 100% | N/A |
| Cover Traffic | N/A | 5-15s | 3-8s | N/A |

## Transport Support

The client auto-detects transport from the DNS address format:
- `host:port` — Plain UDP
- `tcp://host:port` — Plain TCP (2-byte framing)
- `tls://host:port` — DoT (DNS over TLS with uTLS fingerprinting)
- `https://host/path` — DoH (DNS over HTTPS with uTLS fingerprinting)

Multi-resolver: comma-separated addresses with health tracking, round-robin, and automatic dead resolver recovery.

## Building

### Server Binary

```bash
cd cmd/noizdns-server

# Current platform
go build -trimpath -ldflags="-s -w" -o noizdns-server .

# Linux amd64
GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o noizdns-server .

# Linux arm64
GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o noizdns-server .
```

### Android Library (gomobile)

From the `gomobile-build/` directory in SlipNet:

```bash
make build       # Builds both full and lite .aar files
make build-full  # Full: arm + arm64
make build-lite  # Lite: arm64 only (noizdns only, no snowflake)
```

Output goes to `app/libs/golibs-full.aar` and `app/libs/golibs-lite.aar`.

### CLI Client

From the `cli/` directory in SlipNet:

```bash
go build -trimpath -ldflags="-s -w -X main.version=v2.3.1" -o slipnet .
```

## Server Usage

### Generate Keys

```bash
# Print to stdout
noizdns-server -gen-key

# Save to files
noizdns-server -gen-key -privkey-file server.key -pubkey-file server.pub
```

### Run Server

Requires Tor pluggable transport environment variables:

```bash
TOR_PT_MANAGED_TRANSPORT_VER=1 \
TOR_PT_SERVER_TRANSPORTS=dnstt \
TOR_PT_SERVER_BINDADDR=dnstt-0.0.0.0:5300 \
TOR_PT_ORPORT=127.0.0.1:1080 \
noizdns-server -privkey-file server.key -mtu 1232 t.example.com
```

### Server Flags

| Flag | Description |
|---|---|
| `-gen-key` | Generate a server keypair |
| `-privkey-file FILE` | Read private key from file |
| `-privkey HEX` | Private key as hex string |
| `-pubkey-file FILE` | Write public key to file (with `-gen-key`) |
| `-mtu SIZE` | Max UDP payload size (default: 1232) |

## Client API (mobile)

```go
import "noizdns/mobile"

// Create client
client, err := mobile.NewClient(
    "8.8.8.8:53",           // DNS resolver(s)
    "t.example.com",         // Tunnel domain
    "aabbccdd...",           // Server public key (hex)
    "127.0.0.1:1080",       // Local SOCKS5 listen address
)

// Configure mode
client.SetNoizMode(true)        // Enable NoizDNS encoding
client.SetStealthMode(true)     // Enable stealth (requires NoizMode)
client.SetMaxPayload(100)       // Optional: cap payload size

// Start tunnel
err = client.Start()

// Stop tunnel
client.Stop()
```

## Packet Structure

```
Upstream (client → server):

  [ClientID: 8 bytes]
  [Padding count: 1 byte (224 + n)]
  [Padding: n random bytes]
  [Data length: 1 byte (if data present)]
  [Data: up to ~100 bytes]
        ↓
  Base36 encode (with 0x01 marker prefix)
        ↓
  Split into variable-length labels (28-42 chars)
        ↓
  Prepend CDN prefix labels (optional/always)
        ↓
  Append tunnel domain
        ↓
  DNS TXT query with EDNS0 (1232 byte payload)
```

## Capacity

For a domain like `t.example.com`:
- Available DNS name space: ~220 bytes
- After CDN prefix reservation (20 bytes): ~200 bytes
- After label overhead: ~196 base36 chars
- Payload capacity: ~121 bytes per query
- Effective MTU (after headers): ~108 bytes

## Dependencies

- `github.com/xtaci/kcp-go/v5` — KCP protocol
- `github.com/xtaci/smux` — Stream multiplexing
- `github.com/flynn/noise` — Noise protocol encryption
- `github.com/refraction-networking/utls` — uTLS fingerprinting
- `www.bamsoftware.com/git/dnstt.git` — Core DNS tunnel (local override)
- `gitlab.torproject.org/.../goptlib` — Pluggable transport library
