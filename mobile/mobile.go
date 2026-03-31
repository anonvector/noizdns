// Package mobile provides a gomobile-compatible API for the DNSTT client.
//
// It supports four DNS transport modes, auto-detected from the dnsAddr
// parameter passed to NewClient:
//
//   - "https://..." → DoH (DNS over HTTPS) with HTTP/2 and uTLS fingerprinting
//   - "tls://host:port" → DoT (DNS over TLS) with uTLS fingerprinting
//   - "tcp://host:port" → plain TCP DNS (2-byte length framing, no TLS)
//   - "host:port" → plain UDP DNS
package mobile

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
	"golang.org/x/net/http2"
	"golang.org/x/net/proxy"
	noizdns "noizdns/client"
	"www.bamsoftware.com/git/dnstt.git/dns"
	dnsttclient "www.bamsoftware.com/git/dnstt.git/dnstt-client/lib"
	"www.bamsoftware.com/git/dnstt.git/noise"
	"www.bamsoftware.com/git/dnstt.git/turbotunnel"
)

// smux streams will be closed after this much time without receiving data.
const idleTimeout = 2 * time.Minute

// Default uTLS fingerprint distribution (matches upstream default).
const defaultUTLSDistribution = "4*random,3*Firefox_120,1*Firefox_105,3*Chrome_120,1*Chrome_102,1*iOS_14,1*iOS_13"

// numPadding matches the zero-padding constant in client/stealth.go's encodePayload().
// Data queries already vary (different payloads); poll queries have their own padding.
const numPadding = 0

// DnsttClient wraps a DNSTT tunnel client with Start/Stop lifecycle.
type DnsttClient struct {
	dnsAddr      string
	tunnelDomain string
	pubkey       []byte
	listenAddr   string

	// authoritativeMode selects aggressive settings for self-hosted DNS
	// resolvers (more senders, larger poll burst, faster KCP, bigger buffers).
	authoritativeMode bool

	// maxPayload caps the KCP MTU (bytes per DNS query payload).
	// Default 100. Lower values produce smaller, less conspicuous DNS
	// queries at the cost of throughput. 0 = use full capacity.
	maxPayload int

	// edns0Size overrides the EDNS(0) UDP payload size advertised in queries.
	// 0 = 1232 (default, RFC 8020). Configurable via SetEDNS0Size.
	edns0Size int

	// noizMode enables NoizDNS features (cover traffic, custom sender,
	// shorter QNAME, tuned polling). When false, uses original dnstt
	// defaults for maximum compatibility and stability.
	noizMode bool

	// stealthMode enables variable-length label splitting and aggressive
	// cover traffic. Trades throughput for DPI resistance. Requires noizMode.
	stealthMode bool

	// deviceManufacturer is used to filter cover traffic domains that
	// Chinese OEM ROMs (MIUI, EMUI) intercept.
	deviceManufacturer string

	// utlsDistribution overrides the default uTLS fingerprint distribution.
	// Empty string = use default. "none" = disable uTLS.
	// Single value (e.g. "Chrome_120") = use that exact fingerprint every time.
	// Weighted (e.g. "3*Chrome_120,1*Firefox_120") = random from distribution.
	utlsDistribution string

	// socksUser/socksPass are injected automatically during the SOCKS5
	// handshake so clients (browsers, curl) never need to provide credentials.
	socksUser string
	socksPass string

	// socksProxyAddr is the upstream SOCKS5 proxy address ("host:port") to route
	// DNS transport connections through. Empty = direct connection (default).
	// Used when DNSTT is a chain layer behind another proxy (e.g., SSH → DNSTT).
	socksProxyAddr string
	socksProxyUser string
	socksProxyPass string

	mu            sync.Mutex
	running       bool
	cancel        context.CancelFunc
	listener      net.Listener
	transportConn net.PacketConn // raw UDP/DoH/DoT/TCP transport — closed in Stop to kill sendLoop immediately
	kcpConn       net.Conn      // KCP connection — deadline-forced in Stop to prevent blocking Close
}

// NewClient creates a new DNSTT client. Transport is auto-detected from dnsAddr:
//
//   - "https://..." → DoH (HTTP/2 + uTLS fingerprint)
//   - "tls://host:port" → DoT (TLS + uTLS fingerprint)
//   - "tcp://host:port" → plain TCP DNS
//   - "host:port" → UDP
func NewClient(dnsAddr, tunnelDomain, publicKey, listenAddr string) (*DnsttClient, error) {
	if tunnelDomain == "" {
		return nil, fmt.Errorf("tunnel domain is required")
	}
	if publicKey == "" {
		return nil, fmt.Errorf("public key is required")
	}
	if listenAddr == "" {
		return nil, fmt.Errorf("listen address is required")
	}

	pubkey, err := noise.DecodeKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid public key: %v", err)
	}

	return &DnsttClient{
		dnsAddr:      dnsAddr,
		tunnelDomain: tunnelDomain,
		pubkey:       pubkey,
		listenAddr:   listenAddr,
	}, nil
}

// SetAuthoritativeMode enables or disables aggressive query-rate settings.
// When true (for self-hosted / authoritative DNS resolvers):
//   - DoH senders: 32 (vs 8)
//   - pollLimit: 16 (vs 8)
//   - KCP turbo mode with larger windows and buffers
//   - Faster polling (200ms init, 4s max vs 500ms/10s)
//
// Must be called before Start.
func (c *DnsttClient) SetAuthoritativeMode(enabled bool) {
	c.authoritativeMode = enabled
}

// SetNoizMode enables NoizDNS features: cover traffic, custom sender hooks,
// shorter QNAME (150 bytes), and tuned polling for ISP resolver blending.
// When disabled (default), uses original dnstt defaults (full 255 QNAME,
// simple polling, no cover traffic) for maximum stability.
// Must be called before Start.
func (c *DnsttClient) SetNoizMode(enabled bool) {
	c.noizMode = enabled
}

// SetStealthMode enables variable-length DNS label splitting and aggressive
// cover traffic. Queries use randomized label sizes (15-40 chars) instead of
// the fixed 63-byte labels that DPI fingerprints. Data queries also get random
// padding to vary QNAME length. Cover traffic interval drops to 5-15s.
// Throughput is slightly lower (~10%) due to label overhead.
// Must be called before Start.
func (c *DnsttClient) SetStealthMode(enabled bool) {
	c.stealthMode = enabled
}

// SetMaxPayload caps the per-query payload size (KCP MTU) to produce
// smaller, less conspicuous DNS queries. 0 = use full capacity (default).
// Must be called before Start.
func (c *DnsttClient) SetMaxPayload(size int) {
	c.maxPayload = size
}

// SetEDNS0Size overrides the EDNS(0) UDP payload size advertised in DNS queries.
// This controls the maximum response size the server will send back.
// 0 = 1232 (default, RFC 8020). Must be called before Start.
func (c *DnsttClient) SetEDNS0Size(size int) {
	c.edns0Size = size
}

// SetUTLSFingerprint overrides the uTLS fingerprint selection.
// Accepts a single fingerprint name (e.g. "Chrome_120", "Firefox_120", "iOS_14",
// "random") for a fixed fingerprint every run, or a weighted distribution
// (e.g. "3*Chrome_120,1*Firefox_120") for random selection.
// "none" disables uTLS entirely.
// Empty string uses the default random distribution.
// Must be called before Start.
func (c *DnsttClient) SetUTLSFingerprint(fingerprint string) {
	c.utlsDistribution = fingerprint
}

// SetDeviceManufacturer provides the device manufacturer string (e.g. "Xiaomi")
// so cover traffic can skip domains that Chinese OEM ROMs intercept.
// Must be called before Start.
func (c *DnsttClient) SetDeviceManufacturer(manufacturer string) {
	c.deviceManufacturer = manufacturer
}

// SetSocksCredentials sets the SOCKS5 username and password to inject
// automatically during the handshake. Clients (browsers, curl) connect
// to the local proxy without credentials; the CLI handles auth transparently.
// Must be called before Start.
func (c *DnsttClient) SetSocksCredentials(user, pass string) {
	c.socksUser = user
	c.socksPass = pass
}

// SetSOCKS5Proxy configures an upstream SOCKS5 proxy for DNS transport
// connections. When set, all DNS queries (DoH/DoT/TCP) will be routed through
// the proxy. UDP transport is auto-promoted to TCP since SOCKS5 is TCP-only.
// Must be called before Start.
func (c *DnsttClient) SetSOCKS5Proxy(addr, username, password string) {
	c.socksProxyAddr = addr
	c.socksProxyUser = username
	c.socksProxyPass = password
}

// socksDialer returns a proxy.Dialer configured for the upstream SOCKS5 proxy,
// or proxy.Direct if no proxy is configured.
func (c *DnsttClient) socksDialer() (proxy.Dialer, error) {
	if c.socksProxyAddr == "" {
		return proxy.Direct, nil
	}
	var auth *proxy.Auth
	if c.socksProxyUser != "" {
		auth = &proxy.Auth{User: c.socksProxyUser, Password: c.socksProxyPass}
	}
	return proxy.SOCKS5("tcp", c.socksProxyAddr, auth, proxy.Direct)
}

// Start begins the DNSTT tunnel in a background goroutine.
func (c *DnsttClient) Start() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.running {
		return fmt.Errorf("client is already running")
	}

	ctx, cancel := context.WithCancel(context.Background())
	c.cancel = cancel

	// Parse the tunnel domain.
	domain, err := dns.ParseName(c.tunnelDomain)
	if err != nil {
		cancel()
		return fmt.Errorf("invalid tunnel domain: %v", err)
	}

	// Sample uTLS fingerprint.
	utlsDist := defaultUTLSDistribution
	if c.utlsDistribution != "" {
		utlsDist = c.utlsDistribution
	}
	utlsID, err := dnsttclient.SampleUTLSDistribution(utlsDist)
	if err != nil {
		cancel()
		return fmt.Errorf("sampling uTLS distribution: %v", err)
	}
	if utlsID != nil {
		log.Printf("uTLS fingerprint %s %s", utlsID.Client, utlsID.Version)
	}

	// Create transport based on address prefix.
	// dnsAddr may be comma-separated for multi-resolver support (UDP/DoT/TCP).
	var remoteAddr net.Addr
	var pconn net.PacketConn

	switch {
	case strings.HasPrefix(c.dnsAddr, "https://"):
		// DoH — HTTP/2 with uTLS fingerprint camouflage (single URL only).
		var rt http.RoundTripper
		if utlsID == nil {
			transport := http.DefaultTransport.(*http.Transport).Clone()
			transport.Proxy = nil
			if c.socksProxyAddr != "" {
				baseDialer, dErr := c.socksDialer()
				if dErr != nil {
					cancel()
					return fmt.Errorf("creating SOCKS5 dialer for DoH: %v", dErr)
				}
				transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
					return proxyDial(ctx, baseDialer, network, addr)
				}
				log.Printf("DoH: routing through SOCKS5 proxy %s", c.socksProxyAddr)
			}
			rt = transport
		} else {
			if c.socksProxyAddr != "" {
				baseDialer, dErr := c.socksDialer()
				if dErr != nil {
					cancel()
					return fmt.Errorf("creating SOCKS5 dialer for DoH+uTLS: %v", dErr)
				}
				rt = &socks5UTLSRoundTripper{
					clientHelloID: utlsID,
					baseDialer:    baseDialer,
				}
				log.Printf("DoH+uTLS: routing through SOCKS5 proxy %s", c.socksProxyAddr)
			} else {
				rt = dnsttclient.NewUTLSRoundTripper(nil, utlsID)
			}
		}
		numSenders := 8
		var httpConfig *dnsttclient.HTTPPacketConnConfig
		if c.authoritativeMode {
			numSenders = 32
		} else {
			httpConfig = &dnsttclient.HTTPPacketConnConfig{
				RetryAfterDefault: 2 * time.Second,
				SleepOnRateLimit:  true,
			}
		}
		pconn, err = dnsttclient.NewHTTPPacketConnWithConfig(rt, c.dnsAddr, numSenders, httpConfig)
		if err != nil {
			cancel()
			return fmt.Errorf("creating DoH transport: %v", err)
		}
		remoteAddr = turbotunnel.DummyAddr{}

	case strings.Contains(c.dnsAddr, "tls://"):
		// DoT — TLS with uTLS fingerprint camouflage.
		// May be comma-separated for multi-resolver (e.g. "tls://1.1.1.1:853,tls://8.8.8.8:853").
		var dialTLSContext func(ctx context.Context, network, addr string) (net.Conn, error)
		if utlsID == nil {
			if c.socksProxyAddr != "" {
				baseDialer, dErr := c.socksDialer()
				if dErr != nil {
					cancel()
					return fmt.Errorf("creating SOCKS5 dialer for DoT: %v", dErr)
				}
				dialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
					conn, cErr := proxyDial(ctx, baseDialer, "tcp", addr)
					if cErr != nil {
						return nil, cErr
					}
					host, _, _ := net.SplitHostPort(addr)
					tlsConn := tls.Client(conn, &tls.Config{ServerName: host})
					if hErr := tlsConn.HandshakeContext(ctx); hErr != nil {
						conn.Close()
						return nil, hErr
					}
					return tlsConn, nil
				}
				log.Printf("DoT: routing through SOCKS5 proxy %s", c.socksProxyAddr)
			} else {
				dialTLSContext = (&tls.Dialer{}).DialContext
			}
		} else {
			baseDialer, dErr := c.socksDialer()
			if dErr != nil {
				cancel()
				return fmt.Errorf("creating SOCKS5 dialer for DoT+uTLS: %v", dErr)
			}
			if c.socksProxyAddr != "" {
				log.Printf("DoT+uTLS: routing through SOCKS5 proxy %s", c.socksProxyAddr)
			}
			dialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				return utlsDialContext(ctx, network, addr, nil, utlsID, baseDialer)
			}
		}

		addrs := strings.Split(c.dnsAddr, ",")
		if len(addrs) == 1 {
			// Single resolver — no MultiPacketConn overhead.
			dotAddr := strings.TrimPrefix(strings.TrimSpace(addrs[0]), "tls://")
			pconn, err = dnsttclient.NewTLSPacketConn(dotAddr, dialTLSContext)
			if err != nil {
				cancel()
				return fmt.Errorf("creating DoT transport: %v", err)
			}
		} else {
			// Multiple resolvers — create a transport per address.
			var transports []net.PacketConn
			var tAddrs []net.Addr
			for _, a := range addrs {
				dotAddr := strings.TrimPrefix(strings.TrimSpace(a), "tls://")
				t, tErr := dnsttclient.NewTLSPacketConn(dotAddr, dialTLSContext)
				if tErr != nil {
					// Close any already-created transports.
					for _, prev := range transports {
						prev.Close()
					}
					cancel()
					return fmt.Errorf("creating DoT transport for %s: %v", dotAddr, tErr)
				}
				transports = append(transports, t)
				tAddrs = append(tAddrs, turbotunnel.DummyAddr{})
			}
			pconn = NewSmartMultiPacketConn(transports, tAddrs)
			log.Printf("multi-resolver DoT: %d transports (smart)", len(transports))
		}
		remoteAddr = turbotunnel.DummyAddr{}

	case strings.Contains(c.dnsAddr, "tcp://"):
		// Plain TCP DNS — same 2-byte length framing as DoT but without TLS.
		// May be comma-separated for multi-resolver (e.g. "tcp://1.1.1.1:53,tcp://8.8.8.8:53").
		// Hostnames are resolved by Go's net.Dialer (e.g. "tcp://dns.google:53").
		var dialTCPContext func(ctx context.Context, network, addr string) (net.Conn, error)
		if c.socksProxyAddr != "" {
			baseDialer, dErr := c.socksDialer()
			if dErr != nil {
				cancel()
				return fmt.Errorf("creating SOCKS5 dialer for TCP: %v", dErr)
			}
			dialTCPContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				return proxyDial(ctx, baseDialer, "tcp", addr)
			}
			log.Printf("TCP: routing through SOCKS5 proxy %s", c.socksProxyAddr)
		} else {
			dialTCPContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
			}
		}

		addrs := strings.Split(c.dnsAddr, ",")
		if len(addrs) == 1 {
			tcpAddr := strings.TrimPrefix(strings.TrimSpace(addrs[0]), "tcp://")
			pconn, err = dnsttclient.NewTLSPacketConn(tcpAddr, dialTCPContext)
			if err != nil {
				cancel()
				return fmt.Errorf("creating TCP transport: %v", err)
			}
		} else {
			var transports []net.PacketConn
			var tAddrs []net.Addr
			for _, a := range addrs {
				tcpAddr := strings.TrimPrefix(strings.TrimSpace(a), "tcp://")
				t, tErr := dnsttclient.NewTLSPacketConn(tcpAddr, dialTCPContext)
				if tErr != nil {
					for _, prev := range transports {
						prev.Close()
					}
					cancel()
					return fmt.Errorf("creating TCP transport for %s: %v", tcpAddr, tErr)
				}
				transports = append(transports, t)
				tAddrs = append(tAddrs, turbotunnel.DummyAddr{})
			}
			pconn = NewSmartMultiPacketConn(transports, tAddrs)
			log.Printf("multi-resolver TCP: %d transports (smart)", len(transports))
		}
		remoteAddr = turbotunnel.DummyAddr{}

	default:
		// Plain UDP — may be comma-separated for multi-resolver.
		if c.socksProxyAddr != "" {
			// Auto-promote UDP to TCP — SOCKS5 is TCP-only.
			// All DNS resolvers accept TCP on port 53 (RFC 7766).
			log.Printf("auto-promoting UDP to TCP: SOCKS5 proxy requires TCP transport")
			baseDialer, dErr := c.socksDialer()
			if dErr != nil {
				cancel()
				return fmt.Errorf("creating SOCKS5 dialer for UDP→TCP promotion: %v", dErr)
			}
			dialTCPContext := func(ctx context.Context, network, addr string) (net.Conn, error) {
				return proxyDial(ctx, baseDialer, "tcp", addr)
			}
			log.Printf("routing DNS through SOCKS5 proxy %s", c.socksProxyAddr)

			addrs := strings.Split(c.dnsAddr, ",")
			if len(addrs) == 1 {
				tcpAddr := strings.TrimSpace(addrs[0])
				pconn, err = dnsttclient.NewTLSPacketConn(tcpAddr, dialTCPContext)
				if err != nil {
					cancel()
					return fmt.Errorf("creating TCP transport (promoted from UDP): %v", err)
				}
			} else {
				var transports []net.PacketConn
				var tAddrs []net.Addr
				for _, a := range addrs {
					tcpAddr := strings.TrimSpace(a)
					t, tErr := dnsttclient.NewTLSPacketConn(tcpAddr, dialTCPContext)
					if tErr != nil {
						for _, prev := range transports {
							prev.Close()
						}
						cancel()
						return fmt.Errorf("creating TCP transport for %s (promoted from UDP): %v", tcpAddr, tErr)
					}
					transports = append(transports, t)
					tAddrs = append(tAddrs, turbotunnel.DummyAddr{})
				}
				pconn = NewSmartMultiPacketConn(transports, tAddrs)
				log.Printf("multi-resolver TCP (promoted from UDP): %d transports (smart)", len(transports))
			}
			remoteAddr = turbotunnel.DummyAddr{}
		} else {
			addrs := strings.Split(c.dnsAddr, ",")
			if len(addrs) == 1 {
				// Single resolver — persistent socket.
				remoteAddr, err = net.ResolveUDPAddr("udp", strings.TrimSpace(addrs[0]))
				if err != nil {
					cancel()
					return fmt.Errorf("resolving UDP address: %v", err)
				}
				pconn, err = net.ListenUDP("udp", nil)
				if err != nil {
					cancel()
					return fmt.Errorf("opening UDP socket: %v", err)
				}
			} else {
				// Multiple resolvers — smart routing, first response wins.
				var udpAddrs []*net.UDPAddr
				for _, a := range addrs {
					addr, rErr := net.ResolveUDPAddr("udp", strings.TrimSpace(a))
					if rErr != nil {
						cancel()
						return fmt.Errorf("resolving UDP address %s: %v", a, rErr)
					}
					udpAddrs = append(udpAddrs, addr)
				}
				sconn, sErr := NewSmartUDPConn(udpAddrs)
				if sErr != nil {
					cancel()
					return fmt.Errorf("opening UDP socket: %v", sErr)
				}
				pconn = sconn
				remoteAddr = turbotunnel.DummyAddr{}
				log.Printf("multi-resolver UDP: %d resolvers (smart)", len(udpAddrs))
			}
		}
	}

	// Save the raw transport conn so we can close it explicitly. The
	// wrapping layers (DNSPacketConn, AddrNormConn) don't propagate
	// Close to the underlying transport, so PerQueryUDPConn/SmartMultiPacketConn
	// would leak their healthLoop goroutine without this.
	transportConn := pconn
	c.transportConn = pconn // also store on struct so Stop() can close it immediately

	// Wrap the transport with DNSPacketConn for DNS encoding.
	var dnsConfig *dnsttclient.DNSPacketConnConfig
	if c.authoritativeMode {
		// Aggressive: faster polling for lower latency
		dnsConfig = &dnsttclient.DNSPacketConnConfig{
			PollLimit:     12,
			InitPollDelay: 200 * time.Millisecond,
			MaxPollDelay:  4 * time.Second,
			EDNS0Size:     c.edns0Size,
		}
	} else if c.noizMode && c.stealthMode {
		// Stealth NoizDNS: slower polling with jitter and burst patterns
		// to evade DPI fingerprinting. Trades latency for stealth.
		edns0 := c.edns0Size
		if edns0 == 0 {
			edns0 = 1232
		}
		dnsConfig = &dnsttclient.DNSPacketConnConfig{
			PollLimit:     10,
			InitPollDelay: 200 * time.Millisecond,
			MaxPollDelay:  5 * time.Second,
			PollJitter:    true,
			BurstMode:     true,
			EDNS0Size:     edns0,
		}
	} else if c.noizMode {
		// NoizDNS: responsive polling for fast SSH handshakes and data transfer
		edns0 := c.edns0Size
		if edns0 == 0 {
			edns0 = 1232
		}
		dnsConfig = &dnsttclient.DNSPacketConnConfig{
			PollLimit:     12,
			InitPollDelay: 150 * time.Millisecond,
			MaxPollDelay:  4 * time.Second,
			EDNS0Size:     edns0,
		}
	} else {
		// Plain DNSTT: original upstream defaults for maximum stability
		dnsConfig = &dnsttclient.DNSPacketConnConfig{PollLimit: 8}
	}

	// Cover traffic and optional stealth encoding. Only for NoizDNS on
	// non-authoritative mode (public resolvers where DPI is a concern).
	if c.noizMode && !c.authoritativeMode {
		coverDomains := noizdns.FilterCoverDomains(noizdns.DefaultCoverDomains, c.deviceManufacturer)
		// Cover traffic intervals: stealth uses aggressive 5-15s, normal uses 15-45s.
		coverMin, coverMax := 15*time.Second, 45*time.Second
		if c.stealthMode {
			coverMin, coverMax = 5*time.Second, 15*time.Second
		}

		hooks := &dnsttclient.DNSPacketConnHooks{}
		if len(coverDomains) > 0 {
			cMin, cMax := coverMin, coverMax
			hooks.OnStart = func(transport net.PacketConn, addr net.Addr) {
				go noizdns.CoverTrafficLoop(coverDomains, transport, addr, cMin, cMax)
			}
		}

		// Replace default send to skip random padding in both modes.
		clientID := turbotunnel.NewClientID()
		edns0 := c.edns0Size
		if edns0 == 0 {
			edns0 = 1232
		}
		if c.stealthMode {
			sender := &noizdns.StealthSender{
				ClientID:  clientID,
				Domain:    domain,
				EDNS0Size: edns0,
			}
			hooks.CustomSendFunc = sender.Send
		} else {
			sender := &noizdns.NormalSender{
				ClientID:  clientID,
				Domain:    domain,
				EDNS0Size: edns0,
			}
			hooks.CustomSendFunc = sender.Send
		}
		hooks.ClientID = &clientID

		pconn = dnsttclient.NewDNSPacketConnWithHooks(pconn, remoteAddr, domain, dnsConfig, hooks)
	} else {
		pconn = dnsttclient.NewDNSPacketConnWithConfig(pconn, remoteAddr, domain, dnsConfig)
	}

	// For multi-resolver, normalize addresses on ReadFrom so KCP's address
	// filter doesn't drop packets. KCP compares addr.String() from ReadFrom
	// against remoteAddr.String() — responses from different resolvers would
	// have different addresses and get silently dropped.
	if remoteAddr == (turbotunnel.DummyAddr{}) {
		pconn = &AddrNormConn{PacketConn: pconn, fixedAddr: turbotunnel.DummyAddr{}}
	}

	// Resolve the local TCP listen address.
	localAddr, err := net.ResolveTCPAddr("tcp", c.listenAddr)
	if err != nil {
		pconn.Close()
		cancel()
		return fmt.Errorf("resolving listen address: %v", err)
	}

	c.running = true

	go func() {
		defer transportConn.Close()
		err := c.run(ctx, c.pubkey, domain, localAddr, remoteAddr, pconn)
		if err != nil && ctx.Err() == nil {
			log.Printf("dnstt client: %v", err)
		}
		c.mu.Lock()
		c.running = false
		c.mu.Unlock()
	}()

	return nil
}

// Stop shuts down the DNSTT tunnel.
func (c *DnsttClient) Stop() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.cancel != nil {
		c.cancel()
		c.cancel = nil
	}
	// Force-expire the KCP connection so its Close() (and smux.Close above it)
	// return immediately instead of blocking on retransmit timeouts.
	if c.kcpConn != nil {
		c.kcpConn.SetDeadline(time.Now())
	}
	if c.listener != nil {
		c.listener.Close()
		c.listener = nil
	}
	// Close the raw transport immediately so sendLoop/recvLoop exit
	// instead of retrying on the closed socket for seconds.
	if c.transportConn != nil {
		c.transportConn.Close()
		c.transportConn = nil
	}
	c.running = false
}

// IsRunning returns whether the client is currently running.
func (c *DnsttClient) IsRunning() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.running
}

// dnsNameCapacity returns the number of bytes remaining for encoded data after
// including domain in a DNS name, using the full 255-byte QNAME limit.
func dnsNameCapacity(domain dns.Name) int {
	return dnsNameCapacityWithLimit(domain, 255)
}

// dnsNameCapacityWithLimit is like dnsNameCapacity but allows a custom QNAME
// length limit. Shorter QNAMEs look more like normal DNS traffic.
func dnsNameCapacityWithLimit(domain dns.Name, maxQNAMELen int) int {
	capacity := maxQNAMELen
	capacity -= 1 // null terminator
	for _, label := range domain {
		capacity -= len(label) + 1
	}
	if capacity < 0 {
		return 0
	}
	capacity = capacity * 63 / 64 // label length overhead
	capacity = capacity * 5 / 8   // base32 expansion
	return capacity
}

// utlsDialContext connects to the given network address and initiates a TLS
// handshake with the provided ClientHelloID. If baseDialer is non-nil, the TCP
// connection is established through it (e.g., a SOCKS5 proxy); otherwise a
// direct net.Dialer is used.
func utlsDialContext(ctx context.Context, network, addr string, config *utls.Config, id *utls.ClientHelloID, baseDialer proxy.Dialer) (*utls.UConn, error) {
	if config == nil {
		config = &utls.Config{}
	}
	if config.ServerName == "" {
		config = config.Clone()
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		config.ServerName = host
	}
	var conn net.Conn
	var err error
	if baseDialer != nil {
		conn, err = proxyDial(ctx, baseDialer, network, addr)
	} else {
		conn, err = (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	if err != nil {
		return nil, err
	}
	uconn := utls.UClient(conn, config, *id)
	err = uconn.Handshake()
	if err != nil {
		uconn.Close()
		return nil, err
	}
	return uconn, nil
}

// proxyDial connects to addr through the given dialer, using DialContext if
// available for proper cancellation support.
func proxyDial(ctx context.Context, d proxy.Dialer, network, addr string) (net.Conn, error) {
	if cd, ok := d.(proxy.ContextDialer); ok {
		return cd.DialContext(ctx, network, addr)
	}
	return d.Dial(network, addr)
}

// addrForDial extracts a host:port address from a URL, suitable for dialing.
func addrForDial(u *url.URL) (string, error) {
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		switch u.Scheme {
		case "http":
			port = "80"
		case "https":
			port = "443"
		default:
			return "", fmt.Errorf("unsupported URL scheme %q", u.Scheme)
		}
	}
	return net.JoinHostPort(host, port), nil
}

// socks5UTLSRoundTripper is an http.RoundTripper that uses uTLS for TLS
// connections routed through a SOCKS5 proxy. Needed because the upstream
// NewUTLSRoundTripper hardcodes net.Dialer.
type socks5UTLSRoundTripper struct {
	clientHelloID *utls.ClientHelloID
	config        *utls.Config
	baseDialer    proxy.Dialer
	innerLock     sync.Mutex
	inner         http.RoundTripper
}

func (rt *socks5UTLSRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	switch req.URL.Scheme {
	case "http":
		return http.DefaultTransport.RoundTrip(req)
	case "https":
	default:
		return nil, fmt.Errorf("unsupported URL scheme %q", req.URL.Scheme)
	}

	var err error
	rt.innerLock.Lock()
	if rt.inner == nil {
		rt.inner, err = rt.makeRoundTripper(req)
	}
	rt.innerLock.Unlock()
	if err != nil {
		return nil, err
	}
	return rt.inner.RoundTrip(req)
}

func (rt *socks5UTLSRoundTripper) makeRoundTripper(req *http.Request) (http.RoundTripper, error) {
	addr, err := addrForDial(req.URL)
	if err != nil {
		return nil, err
	}

	bootstrapConn, err := utlsDialContext(req.Context(), "tcp", addr, rt.config, rt.clientHelloID, rt.baseDialer)
	if err != nil {
		return nil, err
	}

	protocol := bootstrapConn.ConnectionState().NegotiatedProtocol

	var lock sync.Mutex
	dialTLS := func(ctx context.Context, network, addr string) (net.Conn, error) {
		lock.Lock()
		defer lock.Unlock()

		if bootstrapConn != nil {
			uconn := bootstrapConn
			bootstrapConn = nil
			return uconn, nil
		}

		uconn, err := utlsDialContext(ctx, "tcp", addr, rt.config, rt.clientHelloID, rt.baseDialer)
		if err != nil {
			return nil, err
		}
		if uconn.ConnectionState().NegotiatedProtocol != protocol {
			return nil, fmt.Errorf("unexpected switch from ALPN %q to %q",
				protocol, uconn.ConnectionState().NegotiatedProtocol)
		}
		return uconn, nil
	}

	switch protocol {
	case http2.NextProtoTLS:
		return &http2.Transport{
			DialTLS: func(network, addr string, _ *tls.Config) (net.Conn, error) {
				return dialTLS(context.Background(), network, addr)
			},
		}, nil
	default:
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.DialTLSContext = dialTLS
		return tr, nil
	}
}

// handle proxies data between a local TCP connection and a smux stream.
// copyBufSize controls the io.CopyBuffer size; 0 means use io.Copy (default 32KB).
// When socksUser is set, it intercepts the SOCKS5 handshake and injects
// credentials automatically so clients never need to supply them.
func handle(local *net.TCPConn, sess *smux.Session, conv uint32, copyBufSize int, socksUser, socksPass string) error {
	if socksUser != "" {
		return handleWithAuth(local, sess, conv, copyBufSize, socksUser, socksPass)
	}

	stream, err := sess.OpenStream()
	if err != nil {
		return fmt.Errorf("session %08x opening stream: %v", conv, err)
	}
	defer func() {
		log.Printf("end stream %08x:%d", conv, stream.ID())
		stream.Close()
	}()
	log.Printf("begin stream %08x:%d", conv, stream.ID())

	doCopy := func(dst io.Writer, src io.Reader) (int64, error) {
		if copyBufSize > 0 {
			return io.CopyBuffer(dst, src, make([]byte, copyBufSize))
		}
		return io.Copy(dst, src)
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, err := doCopy(stream, local)
		if err == io.EOF {
			err = nil
		}
		if err != nil && !errors.Is(err, io.ErrClosedPipe) {
			log.Printf("stream %08x:%d copy stream←local: %v", conv, stream.ID(), err)
		}
		local.CloseRead()
		stream.Close()
	}()
	go func() {
		defer wg.Done()
		_, err := doCopy(local, stream)
		if err == io.EOF {
			err = nil
		}
		if err != nil && !errors.Is(err, io.ErrClosedPipe) {
			log.Printf("stream %08x:%d copy local←stream: %v", conv, stream.ID(), err)
		}
		local.CloseWrite()
	}()
	wg.Wait()

	return err
}

// handleWithAuth intercepts the SOCKS5 handshake, injects the server credentials
// transparently, and tells the client no authentication is needed. This means
// browsers and tools connect to 127.0.0.1:PORT with no credentials regardless
// of whether the server requires username/password auth.
func handleWithAuth(local *net.TCPConn, sess *smux.Session, conv uint32, copyBufSize int, socksUser, socksPass string) error {
	// Read client greeting: [VER NMETHODS METHODS...]
	header := make([]byte, 2)
	if _, err := io.ReadFull(local, header); err != nil {
		return err
	}
	if header[0] != 5 {
		return fmt.Errorf("not SOCKS5 (ver=%d)", header[0])
	}
	methods := make([]byte, int(header[1]))
	if len(methods) > 0 {
		if _, err := io.ReadFull(local, methods); err != nil {
			return err
		}
	}

	// Open smux stream to server.
	stream, err := sess.OpenStream()
	if err != nil {
		local.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
		return fmt.Errorf("session %08x opening stream: %v", conv, err)
	}
	defer func() {
		log.Printf("end stream %08x:%d (auth)", conv, stream.ID())
		stream.Close()
	}()
	log.Printf("begin stream %08x:%d (auth)", conv, stream.ID())

	// Offer the server both no-auth and user/pass so we handle either case.
	if _, err := stream.Write([]byte{5, 2, 0x00, 0x02}); err != nil {
		local.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
		return err
	}
	serverChoice := make([]byte, 2)
	if _, err := io.ReadFull(stream, serverChoice); err != nil {
		local.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
		return fmt.Errorf("reading server auth choice: %v", err)
	}
	switch serverChoice[1] {
	case 0x00:
		// Server is happy with no auth — nothing to do.
	case 0x02:
		// Server requires user/pass — inject credentials from profile.
		authMsg := []byte{0x01, byte(len(socksUser))}
		authMsg = append(authMsg, []byte(socksUser)...)
		authMsg = append(authMsg, byte(len(socksPass)))
		authMsg = append(authMsg, []byte(socksPass)...)
		if _, err := stream.Write(authMsg); err != nil {
			local.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
			return err
		}
		authResp := make([]byte, 2)
		if _, err := io.ReadFull(stream, authResp); err != nil || authResp[1] != 0 {
			local.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
			return fmt.Errorf("SOCKS5 auth rejected by server")
		}
	default:
		local.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
		return fmt.Errorf("server rejected all auth methods (0x%02x)", serverChoice[1])
	}

	// Tell the client: no authentication required.
	if _, err := local.Write([]byte{5, 0}); err != nil {
		return err
	}

	// Read client CONNECT request: [VER CMD RSV ATYP ...] and forward to server.
	reqFixed := make([]byte, 4)
	if _, err := io.ReadFull(local, reqFixed); err != nil {
		return err
	}
	if _, err := stream.Write(reqFixed); err != nil {
		return err
	}
	switch reqFixed[3] {
	case 0x01: // IPv4 (4) + port (2)
		buf := make([]byte, 6)
		if _, err := io.ReadFull(local, buf); err != nil {
			return err
		}
		stream.Write(buf)
	case 0x03: // domain: len(1) + domain + port(2)
		lenB := make([]byte, 1)
		if _, err := io.ReadFull(local, lenB); err != nil {
			return err
		}
		stream.Write(lenB)
		rest := make([]byte, int(lenB[0])+2)
		if _, err := io.ReadFull(local, rest); err != nil {
			return err
		}
		stream.Write(rest)
	case 0x04: // IPv6 (16) + port (2)
		buf := make([]byte, 18)
		if _, err := io.ReadFull(local, buf); err != nil {
			return err
		}
		stream.Write(buf)
	default:
		return fmt.Errorf("unsupported ATYP: %d", reqFixed[3])
	}

	// Forward server CONNECT response to client.
	respFixed := make([]byte, 4)
	if _, err := io.ReadFull(stream, respFixed); err != nil {
		return err
	}
	local.Write(respFixed)
	switch respFixed[3] {
	case 0x01:
		buf := make([]byte, 6)
		io.ReadFull(stream, buf)
		local.Write(buf)
	case 0x03:
		lenB := make([]byte, 1)
		io.ReadFull(stream, lenB)
		local.Write(lenB)
		rest := make([]byte, int(lenB[0])+2)
		io.ReadFull(stream, rest)
		local.Write(rest)
	case 0x04:
		buf := make([]byte, 18)
		io.ReadFull(stream, buf)
		local.Write(buf)
	}
	if respFixed[1] != 0 {
		return fmt.Errorf("CONNECT failed: rep=0x%02x", respFixed[1])
	}

	// Relay data bidirectionally.
	doCopy := func(dst io.Writer, src io.Reader) (int64, error) {
		if copyBufSize > 0 {
			return io.CopyBuffer(dst, src, make([]byte, copyBufSize))
		}
		return io.Copy(dst, src)
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, err := doCopy(stream, local)
		if err != nil && err != io.EOF && !errors.Is(err, io.ErrClosedPipe) {
			log.Printf("stream %08x:%d copy stream←local: %v", conv, stream.ID(), err)
		}
		local.CloseRead()
		stream.Close()
	}()
	go func() {
		defer wg.Done()
		_, err := doCopy(local, stream)
		if err != nil && err != io.EOF && !errors.Is(err, io.ErrClosedPipe) {
			log.Printf("stream %08x:%d copy local←stream: %v", conv, stream.ID(), err)
		}
		local.CloseWrite()
		if err != nil {
			// Stream was forcefully closed (e.g. tunnel disconnect).
			// Close local read to unblock the local→stream goroutine.
			local.CloseRead()
		}
	}()
	wg.Wait()
	return nil
}

// run is the main tunnel loop: KCP → Noise → smux → TCP listener.
func (c *DnsttClient) run(ctx context.Context, pubkey []byte, domain dns.Name, localAddr *net.TCPAddr, remoteAddr net.Addr, pconn net.PacketConn) error {
	defer pconn.Close()

	ln, err := net.ListenTCP("tcp", localAddr)
	if err != nil {
		return fmt.Errorf("opening local listener: %v", err)
	}
	c.mu.Lock()
	c.listener = ln
	c.mu.Unlock()
	defer ln.Close()

	// Close listener when context is canceled.
	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	// QNAME sizing:
	// - Authoritative: full 255-byte QNAME (own resolver, no DPI concern)
	// - Non-authoritative (stealth or not): 150-byte QNAME to avoid DPI detection
	//   (255-byte QNAMEs are a classic DNS tunnel fingerprint on ISP resolvers)
	var nameCapacity int
	if c.authoritativeMode {
		nameCapacity = dnsNameCapacity(domain)
	} else if c.stealthMode {
		nameCapacity = noizdns.StealthNameCapacity(domain, 150)
	} else {
		nameCapacity = dnsNameCapacityWithLimit(domain, 150)
	}
	mtu := nameCapacity - 8 - 1 - numPadding - 1
	if mtu < 80 {
		// Fall back to full capacity if the domain is too long for the short limit.
		if c.stealthMode {
			nameCapacity = noizdns.StealthNameCapacity(domain, 255)
		} else {
			nameCapacity = dnsNameCapacity(domain)
		}
		mtu = nameCapacity - 8 - 1 - numPadding - 1
	}
	if mtu < 80 {
		return fmt.Errorf("domain %s leaves only %d bytes for payload (MTU %d); try using a shorter tunnel domain", domain, mtu)
	}
	maxPayload := c.maxPayload
	if maxPayload == 0 && c.noizMode && !c.authoritativeMode {
		maxPayload = 100 // NoizDNS on ISP resolvers: cap query size to blend with normal DNS
	}
	if maxPayload >= 50 && maxPayload < mtu {
		log.Printf("capping MTU from %d to %d (maxPayload)", mtu, maxPayload)
		mtu = maxPayload
	}
	log.Printf("effective MTU %d", mtu)

	// Open a KCP conn on the PacketConn.
	conn, err := kcp.NewConn2(remoteAddr, nil, 0, 0, pconn)
	if err != nil {
		return fmt.Errorf("opening KCP conn: %v", err)
	}
	// Store KCP conn so Stop() can force-deadline it for fast shutdown.
	c.mu.Lock()
	c.kcpConn = conn
	c.mu.Unlock()
	defer func() {
		log.Printf("end session %08x", conn.GetConv())
		conn.Close()
		c.mu.Lock()
		c.kcpConn = nil
		c.mu.Unlock()
	}()
	log.Printf("begin session %08x", conn.GetConv())

	conn.SetStreamMode(true)
	if c.authoritativeMode {
		// Aggressive: KCP turbo mode — 20ms flush, fast retransmit, 30ms min RTO
		conn.SetNoDelay(1, 20, 2, 1)
		conn.SetACKNoDelay(true)
		conn.SetWindowSize(256, 256)
	} else if c.noizMode {
		// NoizDNS: fast flush + fast retransmit for responsive SSH handshakes
		conn.SetNoDelay(1, 30, 2, 1)
		conn.SetACKNoDelay(true)
		conn.SetWindowSize(192, 192)
	} else {
		conn.SetNoDelay(0, 0, 0, 1)
		conn.SetWindowSize(64, 64)
	}
	if rc := conn.SetMtu(mtu); !rc {
		return fmt.Errorf("failed to set KCP MTU to %d", mtu)
	}

	// Put a Noise channel on top of the KCP conn.
	rw, err := noise.NewClient(conn, pubkey)
	if err != nil {
		return err
	}

	smuxConfig := smux.DefaultConfig()
	smuxConfig.Version = 2
	smuxConfig.KeepAliveTimeout = idleTimeout
	if c.authoritativeMode {
		// Aggressive: larger buffers for better throughput
		smuxConfig.MaxStreamBuffer = 4 * 1024 * 1024   // 4MB (default 64KB)
		smuxConfig.MaxReceiveBuffer = 16 * 1024 * 1024 // 16MB (default 4MB)
	} else if c.noizMode {
		// NoizDNS: larger buffers to reduce stalls on page loads
		smuxConfig.MaxStreamBuffer = 1 * 1024 * 1024   // 1MB (default 64KB)
		smuxConfig.MaxReceiveBuffer = 16 * 1024 * 1024 // 16MB (default 4MB)
	} else {
		// Plain DNSTT: reduce smux keepalive frequency to save battery/data.
		smuxConfig.KeepAliveInterval = 30 * time.Second
	}
	sess, err := smux.Client(rw, smuxConfig)
	if err != nil {
		return fmt.Errorf("opening smux session: %v", err)
	}
	defer sess.Close()

	// Aggressive mode: 128KB copy buffer (default 32KB)
	copyBufSize := 0
	if c.authoritativeMode {
		copyBufSize = 128 * 1024
	}

	// Stream limiter: cap concurrent smux streams to prevent tunnel overload.
	// Browsers open 20-40+ connections per page; without a cap each becomes
	// a smux stream that floods the bandwidth-constrained DNS tunnel.
	var streamSem chan struct{}
	if !c.authoritativeMode {
		streamSem = make(chan struct{}, 32)
	}
	// authoritativeMode: no limit (high-bandwidth self-hosted resolver)

	sessDone := sess.CloseChan()

	for {
		// Set a deadline so Accept unblocks periodically for session
		// health checks. Without this, a dead session isn't detected
		// until the next incoming connection (could be minutes).
		ln.SetDeadline(time.Now().Add(2 * time.Second))
		local, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil // Shutdown requested.
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				// Check if session died while we were waiting.
				select {
				case <-sessDone:
					return fmt.Errorf("session %08x closed", conn.GetConv())
				default:
					continue
				}
			}
			if err, ok := err.(net.Error); ok && err.Temporary() {
				continue
			}
			return err
		}
		// Check between accepted connections too.
		select {
		case <-sessDone:
			local.Close()
			return fmt.Errorf("session %08x closed", conn.GetConv())
		default:
		}
		// Non-blocking: reject immediately if at capacity.
		// Keeps the accept loop responsive for other connections.
		if streamSem != nil {
			select {
			case streamSem <- struct{}{}:
			default:
				local.Close()
				continue
			}
		}
		go func() {
			defer local.Close()
			if streamSem != nil {
				defer func() { <-streamSem }()
			}
			err := handle(local.(*net.TCPConn), sess, conn.GetConv(), copyBufSize, c.socksUser, c.socksPass)
			if err != nil && !sess.IsClosed() {
				log.Printf("handle: %v", err)
			}
		}()
	}
}
