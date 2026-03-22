package main

import (
	"bufio"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"noizdns/mobile"
)

// version is set at build time via: -ldflags="-X main.version=vX.Y.Z"
var version = "dev"

func usage() {
	fmt.Fprintf(flag.CommandLine.Output(), `noizdns-client %s - DNS tunnel client (dnstt-compatible, with optional NoizDNS)

Usage:
  noizdns-client [-doh URL | -dot HOST:PORT | -udp HOST:PORT]
                 [-pubkey HEX | -pubkey-file FILE]
                 [-utls FINGERPRINTS]
                 [-noiz] [-stealth] [-max-payload BYTES]
                 [-device-manufacturer NAME]
                 DOMAIN LOCALADDR:LOCALPORT

Transports (mutually exclusive):
  -doh URL          Use DNS-over-HTTPS resolver at URL (e.g. https://resolver.example/dns-query)
  -dot HOST:PORT    Use DNS-over-TLS resolver (e.g. resolver.example:853)
  -udp HOST:PORT    Use plain UDP resolver (e.g. 1.1.1.1:53)

Public key (required):
  -pubkey HEX       Server public key as 64 hex chars
  -pubkey-file F    File containing 64 hex chars (and optional newline)

uTLS fingerprint:
  -utls DIST        Weighted fingerprint distribution or single label.
                    Same syntax as dnstt-client, e.g.:
                      -utls '3*Firefox_120,2*Chrome_120,1*iOS_14'
                      -utls Firefox_120
                      -utls random
                      -utls none

NoizDNS options (optional; default is plain dnstt):
  -noiz             Enable NoizDNS encoding (base36, variable labels, CDN prefixes, cover traffic)
  -stealth          Stealth mode (requires -noiz): more cover traffic, 100%% CDN prefixes
  -max-payload N    Max DNS payload bytes per query (default: full capacity). Minimum sensible
                    values are 50–60; lower values reduce throughput but make queries smaller.
  -device-manufacturer NAME
                    Device/OEM name (e.g. Xiaomi, Huawei) so NoizDNS can avoid intercepted domains
                    in cover traffic for certain Chinese ROMs.

Examples:
  noizdns-client -doh https://resolver.example/dns-query \
      -pubkey-file server.pub -noiz t.example.com 127.0.0.1:7000

  noizdns-client -dot resolver.example:853 \
      -pubkey 14ca15f5...3d752 -noiz -stealth t.example.com 127.0.0.1:7000

  # Plain dnstt mode (drop-in replacement)
  noizdns-client -udp 1.1.1.1:53 \
      -pubkey-file server.pub t.example.com 127.0.0.1:7000

`, version)
}

func main() {
	var dohURL string
	var dotAddr string
	var udpAddr string
	var pubkeyHex string
	var pubkeyFile string
	var utlsDistribution string
	var enableNoiz bool
	var stealth bool
	var maxPayload int
	var deviceManufacturer string

	// Default uTLS distribution matches noizdns/mobile.
	flag.StringVar(&utlsDistribution, "utls",
		"4*random,3*Firefox_120,1*Firefox_105,3*Chrome_120,1*Chrome_102,1*iOS_14,1*iOS_13",
		"TLS fingerprint distribution (same syntax as dnstt-client; use 'none' to disable uTLS)")
	flag.StringVar(&dohURL, "doh", "", "DNS-over-HTTPS resolver URL (e.g. https://resolver.example/dns-query)")
	flag.StringVar(&dotAddr, "dot", "", "DNS-over-TLS resolver address HOST:PORT")
	flag.StringVar(&udpAddr, "udp", "", "UDP DNS resolver address HOST:PORT")
	flag.StringVar(&pubkeyHex, "pubkey", "", "server public key as 64 hex characters")
	flag.StringVar(&pubkeyFile, "pubkey-file", "", "file containing server public key hex")
	flag.BoolVar(&enableNoiz, "noiz", false, "enable NoizDNS encoding (base36, variable labels, CDN prefixes, cover traffic)")
	flag.BoolVar(&stealth, "stealth", false, "enable NoizDNS stealth mode (requires -noiz)")
	flag.IntVar(&maxPayload, "max-payload", 0, "max DNS payload bytes per query (0 = full capacity)")
	flag.StringVar(&deviceManufacturer, "device-manufacturer", "", "device manufacturer/OEM for NoizDNS cover traffic filtering (e.g. Xiaomi)")

	flag.Usage = usage
	flag.Parse()

	if flag.NArg() != 2 {
		usage()
		os.Exit(1)
	}

	// Transport selection must be exactly one of -doh, -dot, -udp.
	numTransports := 0
	if dohURL != "" {
		numTransports++
	}
	if dotAddr != "" {
		numTransports++
	}
	if udpAddr != "" {
		numTransports++
	}
	if numTransports != 1 {
		fmt.Fprintln(os.Stderr, "error: must specify exactly one of -doh, -dot, or -udp")
		os.Exit(1)
	}

	if pubkeyHex == "" && pubkeyFile == "" {
		fmt.Fprintln(os.Stderr, "error: must specify -pubkey or -pubkey-file")
		os.Exit(1)
	}

	if pubkeyHex != "" && pubkeyFile != "" {
		fmt.Fprintln(os.Stderr, "error: specify only one of -pubkey or -pubkey-file")
		os.Exit(1)
	}

	// Read pubkey from file if needed.
	if pubkeyFile != "" {
		f, err := os.Open(pubkeyFile)
		if err != nil {
			log.Fatalf("failed to open pubkey file: %v", err)
		}
		defer f.Close()

		sc := bufio.NewScanner(f)
		if sc.Scan() {
			pubkeyHex = strings.TrimSpace(sc.Text())
		}
		if err := sc.Err(); err != nil {
			log.Fatalf("failed to read pubkey file: %v", err)
		}
	}

	if len(pubkeyHex) != 64 {
		log.Fatalf("public key must be 64 hex characters, got %d", len(pubkeyHex))
	}
	if _, err := hex.DecodeString(pubkeyHex); err != nil {
		log.Fatalf("invalid pubkey hex: %v", err)
	}

	domain := flag.Arg(0)
	listenAddr := flag.Arg(1)

	if domain == "" {
		log.Fatal("DOMAIN is required")
	}
	if !strings.Contains(listenAddr, ":") {
		log.Fatal("LOCALADDR:LOCALPORT must contain ':'")
	}

	// Map dnstt-style transport flags to noizdns/mobile dnsAddr.
	var dnsAddr string
	switch {
	case dohURL != "":
		dnsAddr = dohURL
	case dotAddr != "":
		dnsAddr = "tls://" + dotAddr
	case udpAddr != "":
		dnsAddr = udpAddr
	}

	// Construct client.
	client, err := mobile.NewClient(dnsAddr, domain, pubkeyHex, listenAddr)
	if err != nil {
		log.Fatalf("failed to create client: %v", err)
	}

	// uTLS override, if any.
	if utlsDistribution != "" {
		client.SetUTLSFingerprint(utlsDistribution)
	}

	// NoizDNS / stealth configuration.
	if enableNoiz {
		client.SetNoizMode(true)
		if stealth {
			client.SetStealthMode(true)
		}
	}

	if maxPayload > 0 {
		client.SetMaxPayload(maxPayload)
	}

	if deviceManufacturer != "" {
		client.SetDeviceManufacturer(deviceManufacturer)
	}

	if err := client.Start(); err != nil {
		log.Fatalf("failed to start tunnel: %v", err)
	}

	// Wait for termination signal.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	done := make(chan struct{})
	go func() {
		client.Stop()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		// Timed out, forcing exit.
	}
}

