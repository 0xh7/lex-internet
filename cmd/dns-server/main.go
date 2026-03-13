package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/0xh7/lex-internet/pkg/dns"
)

func main() {
	listenAddr := flag.String("listen", ":8053", "listen address")
	upstream := flag.String("upstream", "8.8.8.8:53,8.8.4.4:53", "upstream nameservers (comma-separated)")
	zoneDir := flag.String("zones", "", "directory containing zone files")
	cacheSize := flag.Int("cache-size", 10000, "max cache entries")
	verbose := flag.Bool("v", false, "verbose logging")
	flag.Parse()

	zones := make(map[string]*dns.Zone)
	if *zoneDir != "" {
		entries, err := os.ReadDir(*zoneDir)
		if err != nil {
			log.Fatalf("failed to read zone directory: %v", err)
		}
		for _, e := range entries {
			if e.IsDir() || !isZoneFile(e.Name()) {
				continue
			}
			path := filepath.Join(*zoneDir, e.Name())
			z, err := dns.LoadZoneFile(path)
			if err != nil {
				log.Printf("failed to load zone %s: %v", path, err)
				continue
			}
			zones[strings.ToLower(z.Origin)] = z
			log.Printf("loaded zone: %s (%s)", z.Origin, path)
		}
	}

	nameservers := strings.Split(*upstream, ",")
	resolver := dns.NewResolver(nameservers...)
	resolver.SetTimeout(3 * time.Second)

	cache := dns.NewCache(*cacheSize)
	defer cache.Close()

	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Message) {
		if len(r.Questions) == 0 {
			resp := dns.NewResponse(r, dns.RCodeFormErr, nil)
			w.WriteMsg(resp)
			return
		}

		q := r.Questions[0]
		if *verbose {
			log.Printf("query: %s %s %s from %s",
				q.Name, dns.TypeToString(q.Type), dns.ClassToString(q.Class), w.RemoteAddr())
		}

		name := strings.TrimSuffix(strings.ToLower(q.Name), ".")
		for suffix := name; suffix != ""; {
			if z, ok := zones[suffix]; ok {
				z.ServeDNS(w, r)
				return
			}
			dot := strings.IndexByte(suffix, '.')
			if dot < 0 {
				break
			}
			suffix = suffix[dot+1:]
		}

		msg, err := resolver.Resolve(q.Name, q.Type)
		if err != nil {
			if *verbose {
				log.Printf("upstream error for %s: %v", q.Name, err)
			}
			resp := dns.NewResponse(r, dns.RCodeServFail, nil)
			w.WriteMsg(resp)
			return
		}

		msg.Header.ID = r.Header.ID
		w.WriteMsg(msg)
	})

	cached := dns.NewCachingHandler(cache, handler)
	srv := dns.NewServer(*listenAddr, cached)

	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("failed to start UDP listener: %v", err)
	}
	if err := srv.ListenAndServeTCP(); err != nil {
		log.Fatalf("failed to start TCP listener: %v", err)
	}

	host, port, _ := net.SplitHostPort(*listenAddr)
	if host == "" {
		host = "0.0.0.0"
	}
	fmt.Printf("dns server listening on %s:%s (udp+tcp)\n", host, port)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	fmt.Println("\nshutting down...")
	srv.Shutdown()
}

func isZoneFile(name string) bool {
	return strings.HasSuffix(name, ".zone") ||
		strings.HasSuffix(name, ".db") ||
		strings.HasPrefix(name, "db.")
}
