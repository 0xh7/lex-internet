package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
)

func main() {
	filePath := flag.String("f", "", "file to send")
	flag.Parse()

	if flag.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "usage: tcp-client [flags] host:port\n")
		os.Exit(1)
	}

	addr := flag.Arg(0)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		log.Fatalf("connect: %v", err)
	}
	defer conn.Close()
	log.Printf("connected to %s", addr)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go func() {
		<-sig
		conn.Close()
		os.Exit(0)
	}()

	if *filePath != "" {
		sendFile(conn, *filePath)
		return
	}

	interactive(conn)
}

func sendFile(conn net.Conn, path string) {
	f, err := os.Open(path)
	if err != nil {
		log.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()

	n, err := io.Copy(conn, f)
	if err != nil {
		log.Fatalf("send: %v", err)
	}
	log.Printf("sent %d bytes from %s", n, path)

	buf := make([]byte, 4096)
	if tcp, ok := conn.(*net.TCPConn); ok {
		tcp.CloseWrite()
	}
	for {
		nr, err := conn.Read(buf)
		if nr > 0 {
			os.Stdout.Write(buf[:nr])
		}
		if err != nil {
			break
		}
	}
}

func interactive(conn net.Conn) {
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 4096)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				os.Stdout.Write(buf[:n])
			}
			if err != nil {
				if err != io.EOF {
					log.Printf("read: %v", err)
				}
				return
			}
		}
	}()

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := scanner.Text() + "\n"
		if _, err := conn.Write([]byte(line)); err != nil {
			log.Printf("write: %v", err)
			break
		}
	}
	if err := scanner.Err(); err != nil {
		log.Printf("stdin: %v", err)
	}

	if tcp, ok := conn.(*net.TCPConn); ok {
		tcp.CloseWrite()
	}
	wg.Wait()
}
