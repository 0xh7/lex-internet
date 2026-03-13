package main

import (
	"flag"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/0xh7/lex-internet/pkg/nat"
)

const protocolTCP = 6

func main() {
	listenAddr := flag.String("listen", ":9000", "public listen address")
	internalAddr := flag.String("internal", "127.0.0.1:8080", "internal upstream address")
	externalIPFlag := flag.String("external", "127.0.0.1", "external IP used in NAT mappings")
	flag.Parse()

	externalIP := net.ParseIP(*externalIPFlag)
	if externalIP == nil {
		log.Fatalf("invalid external IP: %s", *externalIPFlag)
	}

	table := nat.NewNATTable(externalIP, [2]uint16{40000, 60000})
	ln, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()

	var wg sync.WaitGroup
	done := make(chan struct{})

	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				table.Cleanup()
				logMappings(table)
			}
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		close(done)
		ln.Close()
	}()

	log.Printf("nat gateway listening on %s and forwarding to %s", *listenAddr, *internalAddr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-done:
				wg.Wait()
				return
			default:
			}
			log.Printf("nat: accept error: %v", err)
			continue
		}

		wg.Add(1)
		go func(client net.Conn) {
			defer wg.Done()
			defer client.Close()

			remoteAddr, _ := client.RemoteAddr().(*net.TCPAddr)
			if remoteAddr == nil {
				log.Printf("nat: unexpected client address %T", client.RemoteAddr())
				return
			}

			mappedIP, mappedPort := table.Translate(remoteAddr.IP, uint16(remoteAddr.Port), protocolTCP)
			if mappedIP == nil || mappedPort == 0 {
				log.Printf("nat: no ports available for %s", remoteAddr)
				return
			}

			upstream, err := net.DialTimeout("tcp", *internalAddr, 10*time.Second)
			if err != nil {
				log.Printf("nat: upstream dial %s failed: %v", *internalAddr, err)
				return
			}
			defer upstream.Close()

			log.Printf("nat: %s -> %s:%d -> %s", remoteAddr, mappedIP, mappedPort, *internalAddr)

			var relayWG sync.WaitGroup
			relayWG.Add(2)

			go func() {
				defer relayWG.Done()
				io.Copy(upstream, client)
				if tcp, ok := upstream.(*net.TCPConn); ok {
					tcp.CloseWrite()
				}
			}()

			go func() {
				defer relayWG.Done()
				io.Copy(client, upstream)
				if tcp, ok := client.(*net.TCPConn); ok {
					tcp.CloseWrite()
				}
			}()

			relayWG.Wait()
			table.Cleanup()
		}(conn)
	}
}

func logMappings(table *nat.NATTable) {
	for _, mapping := range table.Snapshot() {
		log.Printf(
			"nat table: %s:%d <-> %s:%d proto=%d expires=%s",
			mapping.InternalIP,
			mapping.InternalPort,
			mapping.ExternalIP,
			mapping.ExternalPort,
			mapping.Protocol,
			time.Until(mapping.Expiry).Round(time.Second),
		)
	}
}
