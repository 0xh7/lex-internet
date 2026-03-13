package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/0xh7/lex-internet/pkg/firewall"
)

func main() {
	rulesFile := flag.String("rules", "firewall.rules", "path to rules config file")
	listen := flag.String("listen", ":9090", "listen address for filtering proxy")
	upstream := flag.String("upstream", "", "upstream address to forward allowed traffic")
	flag.Parse()

	rules, err := firewall.LoadRules(*rulesFile)
	if err != nil {
		log.Fatalf("failed to load rules: %v", err)
	}
	log.Printf("loaded %d firewall rules", rules.Len())

	engine := firewall.NewEngine(rules)
	defer engine.Close()

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	log.Printf("firewall proxy listening on %s", *listen)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				s := engine.Stats()
				log.Printf("stats: allowed=%d denied=%d dropped=%d active_conns=%d",
					s.Allowed, s.Denied, s.Dropped, s.ActiveConns)
			case sig := <-sigCh:
				log.Printf("received %v, shutting down", sig)
				s := engine.Stats()
				fmt.Printf("\nfinal stats: allowed=%d denied=%d dropped=%d\n",
					s.Allowed, s.Denied, s.Dropped)
				ln.Close()
				os.Exit(0)
			}
		}
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			return
		}
		go handleConn(engine, conn, *upstream)
	}
}

func handleConn(engine *firewall.Engine, conn net.Conn, upstream string) {
	defer conn.Close()

	remote, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		log.Printf("unexpected remote address type: %T", conn.RemoteAddr())
		return
	}
	local, ok := conn.LocalAddr().(*net.TCPAddr)
	if !ok {
		log.Printf("unexpected local address type: %T", conn.LocalAddr())
		return
	}

	info := firewall.PacketInfo{
		SrcIP:     remote.IP,
		DstIP:     local.IP,
		SrcPort:   uint16(remote.Port),
		DstPort:   uint16(local.Port),
		Protocol:  "tcp",
		Direction: firewall.Inbound,
	}

	if !engine.Process(info) {
		log.Printf("DENIED %s -> %s", remote, local)
		return
	}

	if upstream == "" {
		log.Printf("ALLOWED %s (no upstream, closing)", remote)
		return
	}

	target, err := net.DialTimeout("tcp", upstream, 10*time.Second)
	if err != nil {
		log.Printf("upstream dial failed: %v", err)
		return
	}
	defer target.Close()

	log.Printf("FORWARD %s -> %s", remote, upstream)

	var wg sync.WaitGroup
	wg.Add(2)
	pipe := func(dst, src net.Conn) {
		defer wg.Done()
		io.Copy(dst, src)
		if tc, ok := dst.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}
	go pipe(target, conn)
	go pipe(conn, target)
	wg.Wait()
}
