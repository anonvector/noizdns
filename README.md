# NoizDNS

Anti-censorship DNS tunnel built on [dnstt](https://www.bamsoftware.com/software/dnstt/).

- Cover traffic — real DNS queries to dilute tunnel ratio
- Stealth mode — variable-length labels to break fixed-63 fingerprint
- Multi-resolver fan-out with health tracking and dead detection
- gomobile API for Android/iOS
- SOCKS5 proxy chaining for transport
- Plain TCP transport
- Authoritative mode with KCP turbo tuning
- Chinese OEM domain filtering for cover traffic
- Backward-compatible server (auto-detects base32 + legacy encoding)

## Features

### Cover Traffic
- Sends periodic legitimate DNS queries to real domains through the same transport
- Dilutes the tunnel-to-total DNS ratio that DPI uses to identify tunnel-only resolver usage
- Mixes international platform domains (Android/iOS background traffic) with domestic domains reachable during internet shutdowns
- Auto-filters domains intercepted by Chinese OEM ROMs (Xiaomi, Huawei, OPPO, etc.)

### Stealth Mode
Variable-length DNS label splitting that breaks the fixed 63-byte label fingerprint DPI uses to identify dnstt:

```
Normal dnstt (fixed 63-char labels):
  ingesrkokreujy6zumkse43vobsxey3bnruwm4tbm5uwy2ltoruwgzlyobuwc3d.jmrxwg2lpovzq.t.example.com
  └──────────────────────── always 63 ──────────────────────────────┘

Stealth mode (random 15-40 char labels):
  ingesrkokreujy6zum.kse43vobsxey3bnruwm4tbm5uwy2lto.ruwgzlyobuwc3djmrxwg2lpovzq.t.example.com
  └────── 18 ───────┘└──────────── 31 ──────────────────┘└─────────── 27 ────────────┘
```

Same data, same base32 encoding, fully backward compatible server decoding (server just concatenates all labels). ~3% throughput cost from label overhead.

Also enables aggressive cover traffic (5-15s intervals vs 15-45s normal).

### Multi-Resolver Health Tracking (`SmartUDPConn`)
- Persistent UDP socket with fan-out to all alive resolvers; KCP deduplicates, fastest wins
- Monitors per-resolver response times with dead detection (12s timeout)
- Automatic dead resolver probing (every 15s) and recovery

### Backward-Compatible Server
The server auto-detects encoding per-query:
- **Fast path**: base32 `[a-z2-7]` — current clients (single-pass detection)
- **Legacy path**: hex or base36 with CDN prefix stripping — old clients

### Transport Support
Auto-detected from the DNS address format:
- `host:port` — Plain UDP (with per-query source port randomization)
- `tcp://host:port` — Plain TCP (2-byte length framing)
- `tls://host:port` — DoT (DNS over TLS with uTLS fingerprinting)
- `https://host/path` — DoH (DNS over HTTPS with uTLS fingerprinting)

Multi-resolver: comma-separated addresses with health tracking and automatic failover.

## Architecture

```
noizdns/
├── client/
│   ├── stealth.go        # Stealth send: variable-length label splitting
│   └── cover.go          # Cover traffic loop and domain filtering
├── server/
│   └── decode.go         # Server-side decoding (base32 fast path + legacy fallback)
├── mobile/
│   ├── mobile.go         # gomobile-compatible client API (package noizdns)
│   └── multi.go          # SmartUDPConn, multi-resolver health tracking
└── cmd/
    ├── noizdns-server/
    │   └── main.go       # Pluggable transport server binary
    └── noizdns-client/
        └── main.go       # CLI client
```

## Client API (mobile)

The mobile package is `noizdns` (not `mobile`) so it can coexist with
`dnstt-mobile/mobile` in the same gomobile build. In Java/Kotlin the
factory class is `noizdns.Noizdns`.

```go
import "noizdns/mobile" // package noizdns

client, err := noizdns.NewClient(
    "8.8.8.8:53",           // DNS resolver(s), comma-separated for multi
    "t.example.com",        // Tunnel domain
    "aabbccdd...",          // Server public key (hex)
    "127.0.0.1:1080",      // Local SOCKS5 listen address
)

// Optional configuration (call before Start)
client.SetStealthMode(true)     // Variable-length labels + aggressive cover traffic
client.SetMaxPayload(50)        // Cap payload size for smaller queries
client.SetAuthoritativeMode(true) // Aggressive settings for self-hosted resolvers
client.SetEDNS0Size(1232)       // EDNS(0) UDP payload size (default: 1232)
client.SetDeviceManufacturer("xiaomi") // Filter intercepted cover domains

err = client.Start()
defer client.Stop()
```

### Connection Modes

| Setting | Authoritative | Normal | Stealth |
|---|---|---|---|
| QNAME limit | 255 bytes | 150 bytes | 150 bytes |
| Label splitting | Fixed 63 | Fixed 63 | Random 15-40 |
| PollLimit | 12 | 10 | 10 |
| MaxPollDelay | 4s | 5s | 5s |
| Poll jitter | no | yes (±30%) | yes (±30%) |
| Burst polling | no | yes | yes |
| Cover traffic | off | 15-45s | 5-15s |
| EDNS(0) size | 4096 | 1232 | 1232 |

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

## Server Installation

For a guided server setup script and installation instructions, see **[SlipGate](https://github.com/anonvector/slipgate)**.

SlipGate automates the full server deployment process including DNS configuration, key generation, and service setup.

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

## Dependencies

- `github.com/xtaci/kcp-go/v5` — KCP protocol
- `github.com/xtaci/smux` — Stream multiplexing
- `github.com/flynn/noise` — Noise protocol encryption
- `github.com/refraction-networking/utls` — uTLS fingerprinting
- `www.bamsoftware.com/git/dnstt.git` — Core DNS tunnel (local override)
- `gitlab.torproject.org/.../goptlib` — Pluggable transport library

## License

MIT — see [LICENSE](LICENSE).
