package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"time"
)

func main() {
	addr := flag.String("l", ":9001", "listen address")
	mode := flag.String("m", "echo", "mode: echo or log")
	flag.Parse()

	laddr, err := net.ResolveUDPAddr("udp4", *addr)
	if err != nil {
		log.Fatalf("resolve: %v", err)
	}

	conn, err := net.ListenUDP("udp4", laddr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	defer conn.Close()

	log.Printf("udp server listening on %s (mode=%s)", *addr, *mode)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go func() {
		<-sig
		log.Println("shutting down")
		conn.Close()
		os.Exit(0)
	}()

	buf := make([]byte, 65535)
	for {
		n, remote, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("read: %v", err)
			return
		}

		switch *mode {
		case "log":
			ts := time.Now().Format("15:04:05.000")
			fmt.Printf("[%s] %s (%d bytes): %s\n", ts, remote, n, string(buf[:n]))
		default:
			if _, err := conn.WriteToUDP(buf[:n], remote); err != nil {
				log.Printf("write to %s: %v", remote, err)
			}
		}
	}
}
