// noizdns-server is the NoizDNS dnstt server. It accepts both standard
// base32 (current clients) and legacy hex/base36 (old clients).
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"www.bamsoftware.com/git/dnstt.git/dns"
	serverlib "www.bamsoftware.com/git/dnstt.git/dnstt-server/lib"
	"www.bamsoftware.com/git/dnstt.git/noise"

	noizdns "noizdns/server"
)

var (
	maxUDPPayload = 1280 - 40 - 8
)

func generateKeypair(privkeyFilename, pubkeyFilename string) (err error) {
	var toDelete []string
	defer func() {
		for _, filename := range toDelete {
			log.Printf("deleting partially written file %s\n", filename)
			if closeErr := os.Remove(filename); closeErr != nil {
				log.Printf("cannot remove %s: %v\n", filename, closeErr)
				if err == nil {
					err = closeErr
				}
			}
		}
	}()

	privkey, err := noise.GeneratePrivkey()
	if err != nil {
		return err
	}
	pubkey := noise.PubkeyFromPrivkey(privkey)

	if privkeyFilename != "" {
		f, err := os.OpenFile(privkeyFilename, os.O_RDWR|os.O_CREATE, 0400)
		if err != nil {
			return err
		}
		toDelete = append(toDelete, privkeyFilename)
		err = noise.WriteKey(f, privkey)
		if err2 := f.Close(); err == nil {
			err = err2
		}
		if err != nil {
			return err
		}
	}

	if pubkeyFilename != "" {
		f, err := os.Create(pubkeyFilename)
		if err != nil {
			return err
		}
		toDelete = append(toDelete, pubkeyFilename)
		err = noise.WriteKey(f, pubkey)
		if err2 := f.Close(); err == nil {
			err = err2
		}
		if err != nil {
			return err
		}
	}

	toDelete = nil

	if privkeyFilename != "" {
		fmt.Printf("privkey written to %s\n", privkeyFilename)
	} else {
		fmt.Printf("privkey %x\n", privkey)
	}
	if pubkeyFilename != "" {
		fmt.Printf("pubkey  written to %s\n", pubkeyFilename)
	} else {
		fmt.Printf("pubkey  %x\n", pubkey)
	}

	return nil
}

func readKeyFromFile(filename string) ([]byte, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = f.Close()
	}()
	return noise.ReadKey(f)
}

func main() {
	var genKey bool
	var udpAddr string
	var privkeyFilename string
	var privkeyString string
	var pubkeyFilename string

	flag.Usage = func() {
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), `Usage:
  %[1]s -gen-key [-privkey-file PRIVKEYFILE] [-pubkey-file PUBKEYFILE]
  %[1]s [-privkey PRIVKEY|-privkey-file PRIVKEYFILE] [-mtu MTU] DOMAIN LISTENADDR UPSTREAMADDR

Example:
  %[1]s -gen-key -privkey-file server.key -pubkey-file server.pub
  %[1]s -privkey-file server.key -mtu 1232 t.example.com 0.0.0.0:53 127.0.0.1:8000

`, os.Args[0])
		flag.PrintDefaults()
	}
	flag.BoolVar(&genKey, "gen-key", false, "generate a server keypair; print to stdout or save to files")
	flag.StringVar(&udpAddr, "udp", "", "UDP address to listen on (legacy, use positional LISTENADDR instead)")
	flag.IntVar(&maxUDPPayload, "mtu", maxUDPPayload, "maximum size of DNS responses")
	flag.StringVar(&privkeyString, "privkey", "", fmt.Sprintf("server private key (%d hex digits)", noise.KeyLen*2))
	flag.StringVar(&privkeyFilename, "privkey-file", "", "read server private key from file (with -gen-key, write to file)")
	flag.StringVar(&pubkeyFilename, "pubkey-file", "", "with -gen-key, write server public key to file")
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.LUTC)

	if genKey {
		if flag.NArg() != 0 || privkeyString != "" {
			flag.Usage()
			os.Exit(1)
		}
		if err := generateKeypair(privkeyFilename, pubkeyFilename); err != nil {
			log.Printf("cannot generate keypair: %v\n", err)
			os.Exit(1)
		}
	} else {
		var listenAddr, upstream string

		switch {
		case udpAddr != "" && flag.NArg() == 2:
			// Legacy -udp flag mode (backward compat with slipgate v1.2)
			listenAddr = udpAddr
			upstream = flag.Arg(1)
		case flag.NArg() == 3:
			// Direct mode: DOMAIN LISTENADDR UPSTREAMADDR
			listenAddr = flag.Arg(1)
			upstream = flag.Arg(2)
		case flag.NArg() == 1:
			// Legacy PT env var mode (backward compat with slipgate v1.3.1)
			bindAddr := os.Getenv("TOR_PT_SERVER_BINDADDR")
			upstream = os.Getenv("TOR_PT_ORPORT")
			if bindAddr == "" || upstream == "" {
				flag.Usage()
				os.Exit(1)
			}
			// Strip "dnstt-" prefix from bind address
			if len(bindAddr) > 6 && bindAddr[:6] == "dnstt-" {
				bindAddr = bindAddr[6:]
			}
			listenAddr = bindAddr
			log.Println("using legacy PT environment variables; consider upgrading slipgate")
		default:
			flag.Usage()
			os.Exit(1)
		}

		domain, err := dns.ParseName(flag.Arg(0))
		if err != nil {
			log.Printf("invalid domain %+q: %v\n", flag.Arg(0), err)
			os.Exit(1)
		}

		{
			upstreamHost, _, err := net.SplitHostPort(upstream)
			if err != nil {
				log.Printf("cannot parse upstream address %+q: %v\n", upstream, err)
				os.Exit(1)
			}
			upstreamIPAddr, err := net.ResolveIPAddr("ip", upstreamHost)
			if err != nil {
				log.Printf("warning: cannot resolve upstream host %+q: %v", upstreamHost, err)
			} else if upstreamIPAddr.IP == nil {
				log.Printf("cannot parse upstream address %+q: missing host in address\n", upstream)
				os.Exit(1)
			}
		}

		if pubkeyFilename != "" {
			log.Printf("-pubkey-file may only be used with -gen-key\n")
			os.Exit(1)
		}

		var privkey []byte
		if privkeyFilename != "" && privkeyString != "" {
			log.Printf("only one of -privkey and -privkey-file may be used\n")
			os.Exit(1)
		} else if privkeyFilename != "" {
			var err error
			privkey, err = readKeyFromFile(privkeyFilename)
			if err != nil {
				log.Printf("cannot read privkey from file: %v\n", err)
				os.Exit(1)
			}
		} else if privkeyString != "" {
			var err error
			privkey, err = noise.DecodeKey(privkeyString)
			if err != nil {
				log.Printf("privkey format error: %v\n", err)
				os.Exit(1)
			}
		}
		if len(privkey) == 0 {
			log.Println("generating a temporary one-time keypair")
			log.Println("use the -privkey or -privkey-file option for a persistent server keypair")
			var err error
			privkey, err = noise.GeneratePrivkey()
			if err != nil {
				log.Println(err)
				os.Exit(1)
			}
		}

		dnsConn, err := net.ListenPacket("udp", listenAddr)
		if err != nil {
			log.Fatalf("opening UDP listener: %v\n", err)
		}
		defer func() {
			_ = dnsConn.Close()
		}()

		log.Printf("listening on %s", listenAddr)

		// Backward-compatible hooks: accepts base32 (fast path for new
		// clients) and auto-detects hex/base36 (legacy clients).
		hooks := noizdns.NewHooks()

		go func() {
			err := serverlib.Run(privkey, domain, upstream, dnsConn, maxUDPPayload, hooks)
			if err != nil {
				log.Fatal(err)
			}
		}()

		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT)

		sig := <-sigChan
		log.Printf("caught signal %q, exiting", sig)
	}
}
