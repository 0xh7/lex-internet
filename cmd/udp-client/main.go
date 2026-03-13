package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"time"
)

func main() {
	data := flag.String("d", "", "data to send (one-shot mode)")
	timeout := flag.Duration("t", 3*time.Second, "read timeout")
	flag.Parse()

	if flag.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "usage: udp-client [flags] host:port\n")
		os.Exit(1)
	}

	addr := flag.Arg(0)
	raddr, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		log.Fatalf("resolve: %v", err)
	}

	conn, err := net.DialUDP("udp4", nil, raddr)
	if err != nil {
		log.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	log.Printf("target: %s", addr)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go func() {
		<-sig
		conn.Close()
		os.Exit(0)
	}()

	if *data != "" {
		oneShot(conn, []byte(*data), *timeout)
		return
	}

	interactive(conn, *timeout)
}

func oneShot(conn *net.UDPConn, payload []byte, timeout time.Duration) {
	if _, err := conn.Write(payload); err != nil {
		log.Fatalf("send: %v", err)
	}
	log.Printf("sent %d bytes", len(payload))

	buf := make([]byte, 65535)
	conn.SetReadDeadline(time.Now().Add(timeout))
	n, err := conn.Read(buf)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			log.Printf("no response (timeout)")
			return
		}
		log.Fatalf("recv: %v", err)
	}
	fmt.Printf("%s\n", buf[:n])
}

func interactive(conn *net.UDPConn, timeout time.Duration) {
	go func() {
		buf := make([]byte, 65535)
		for {
			conn.SetReadDeadline(time.Now().Add(timeout))
			n, err := conn.Read(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				return
			}
			fmt.Printf("< %s\n", buf[:n])
		}
	}()

	scanner := bufio.NewScanner(os.Stdin)
	fmt.Print("> ")
	for scanner.Scan() {
		line := scanner.Text()
		if _, err := conn.Write([]byte(line)); err != nil {
			log.Printf("send: %v", err)
			break
		}
		fmt.Print("> ")
	}
}
