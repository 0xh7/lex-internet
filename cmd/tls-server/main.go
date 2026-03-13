package main

import (
	"crypto/tls"
	"flag"
	"io"
	"log"
	"net"

	itls "github.com/0xh7/lex-internet/pkg/tls"
)

func main() {
	certFile := flag.String("cert", "", "path to certificate PEM file")
	keyFile := flag.String("key", "", "path to private key PEM file")
	listen := flag.String("listen", ":4433", "listen address")
	flag.Parse()

	var cert tls.Certificate
	var err error

	if *certFile != "" && *keyFile != "" {
		cert, err = tls.LoadX509KeyPair(*certFile, *keyFile)
		if err != nil {
			log.Fatalf("failed to load certificate: %v", err)
		}
		log.Printf("loaded certificate from %s", *certFile)
	} else {
		cert, err = itls.GenerateSelfSigned([]string{"localhost", "127.0.0.1"})
		if err != nil {
			log.Fatalf("failed to generate self-signed certificate: %v", err)
		}
		log.Println("generated self-signed certificate")
	}

	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	ln, err := tls.Listen("tcp", *listen, cfg)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	log.Printf("tls echo server listening on %s", *listen)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go handleConn(conn)
	}
}

func handleConn(conn net.Conn) {
	defer conn.Close()
	remote := conn.RemoteAddr()
	log.Printf("connection from %s", remote)

	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			if _, werr := conn.Write(buf[:n]); werr != nil {
				log.Printf("[%s] write error: %v", remote, werr)
				return
			}
		}
		if err != nil {
			if err != io.EOF {
				log.Printf("[%s] read error: %v", remote, err)
			}
			return
		}
	}
}
