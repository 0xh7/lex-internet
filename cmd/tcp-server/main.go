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
	"strings"
	"sync"
	"time"
)

type client struct {
	conn net.Conn
	name string
}

type chatServer struct {
	mu      sync.Mutex
	clients map[net.Conn]*client
}

func newChatServer() *chatServer {
	return &chatServer{clients: make(map[net.Conn]*client)}
}

func (s *chatServer) add(c *client) {
	s.mu.Lock()
	s.clients[c.conn] = c
	s.mu.Unlock()
	s.broadcast(fmt.Sprintf("[%s joined]\n", c.name), c.conn)
	log.Printf("client connected: %s", c.name)
}

func (s *chatServer) remove(conn net.Conn) {
	s.mu.Lock()
	c, ok := s.clients[conn]
	delete(s.clients, conn)
	s.mu.Unlock()
	if ok {
		s.broadcast(fmt.Sprintf("[%s left]\n", c.name), conn)
		log.Printf("client disconnected: %s", c.name)
	}
}

func (s *chatServer) broadcast(msg string, exclude net.Conn) {
	s.mu.Lock()
	targets := make(map[net.Conn]string, len(s.clients))
	for conn, c := range s.clients {
		if conn != exclude {
			targets[conn] = c.name
		}
	}
	s.mu.Unlock()

	for conn, name := range targets {
		conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.WriteString(conn, msg); err != nil {
			log.Printf("write to %s: %v", name, err)
		}
	}
}

func main() {
	addr := flag.String("l", ":9000", "listen address")
	mode := flag.String("m", "echo", "mode: echo or chat")
	flag.Parse()

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}

	log.Printf("tcp server listening on %s (mode=%s)", *addr, *mode)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go func() {
		<-sig
		log.Println("shutting down")
		ln.Close()
		os.Exit(0)
	}()

	switch *mode {
	case "chat":
		runChat(ln)
	default:
		runEcho(ln)
	}
}

func runEcho(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			return
		}
		go handleEcho(conn)
	}
}

func handleEcho(conn net.Conn) {
	defer conn.Close()
	remote := conn.RemoteAddr().String()
	start := time.Now()
	log.Printf("echo: %s connected", remote)

	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			if err != io.EOF {
				log.Printf("echo: %s read: %v", remote, err)
			}
			break
		}
		if _, err := conn.Write(buf[:n]); err != nil {
			log.Printf("echo: %s write: %v", remote, err)
			break
		}
	}

	log.Printf("echo: %s disconnected (duration=%s)", remote, time.Since(start).Round(time.Millisecond))
}

func runChat(ln net.Listener) {
	srv := newChatServer()

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			return
		}
		go handleChat(srv, conn)
	}
}

func handleChat(srv *chatServer, conn net.Conn) {
	defer conn.Close()
	remote := conn.RemoteAddr().String()

	io.WriteString(conn, "Enter your name: ")
	scanner := bufio.NewScanner(conn)
	if !scanner.Scan() {
		return
	}
	name := strings.TrimSpace(scanner.Text())
	if name == "" {
		name = remote
	}

	c := &client{conn: conn, name: name}
	srv.add(c)
	defer srv.remove(conn)

	io.WriteString(conn, fmt.Sprintf("Welcome, %s! Type messages below.\n", name))

	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		msg := fmt.Sprintf("%s: %s\n", name, line)
		srv.broadcast(msg, conn)
	}
}
