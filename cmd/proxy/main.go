package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/0xh7/lex-internet/pkg/proxy"
)

func main() {
	mode := flag.String("mode", "http", "proxy mode: http or socks5")
	listen := flag.String("listen", ":8080", "listen address")
	auth := flag.String("auth", "", "authentication credentials (user:pass, socks5 only)")
	flag.Parse()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	switch strings.ToLower(*mode) {
	case "http":
		p := proxy.NewHTTPProxy(*listen)
		go func() {
			<-sigCh
			log.Println("shutting down...")
			p.Close()
		}()
		if err := p.ListenAndServe(); err != nil {
			log.Fatal(err)
		}

	case "socks5":
		s := proxy.NewSOCKS5(*listen)
		if *auth != "" {
			parts := strings.SplitN(*auth, ":", 2)
			if len(parts) != 2 {
				log.Fatal("auth format: user:pass")
			}
			s.SetAuth(parts[0], parts[1])
		}
		go func() {
			<-sigCh
			log.Println("shutting down...")
			s.Close()
		}()
		if err := s.ListenAndServe(); err != nil {
			log.Fatal(err)
		}

	default:
		log.Fatalf("unknown mode: %s (use http or socks5)", *mode)
	}
}
