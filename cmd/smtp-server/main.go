package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/0xh7/lex-internet/pkg/smtp"
)

type maildirHandler struct {
	dir string
}

func (h *maildirHandler) HandleMessage(from string, to []string, data []byte) error {
	ts := time.Now().UnixNano()
	host, _ := os.Hostname()
	if host == "" {
		host = "localhost"
	}
	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return fmt.Errorf("generate random: %w", err)
	}
	name := fmt.Sprintf("%d.%x.%s", ts, rnd, host)

	tmpDir := filepath.Join(h.dir, "tmp")
	newDir := filepath.Join(h.dir, "new")
	tmpPath := filepath.Join(tmpDir, name)
	newPath := filepath.Join(newDir, name)

	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return fmt.Errorf("write maildir: %w", err)
	}
	if err := os.Rename(tmpPath, newPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("publish maildir message: %w", err)
	}

	log.Printf("smtp-server: stored message from <%s> to %v -> %s", from, to, newPath)
	return nil
}

func main() {
	listen := flag.String("listen", ":2525", "address to listen on")
	domain := flag.String("domain", "localhost", "server domain name")
	maildir := flag.String("maildir", "./maildir", "maildir-style storage directory")
	flag.Parse()

	for _, sub := range []string{"new", "cur", "tmp"} {
		dir := filepath.Join(*maildir, sub)
		if err := os.MkdirAll(dir, 0755); err != nil {
			log.Fatalf("smtp-server: create maildir %s: %v", dir, err)
		}
	}

	handler := &maildirHandler{dir: *maildir}
	srv := smtp.NewServer(*listen, *domain, handler)

	log.Printf("smtp-server: domain=%s, maildir=%s", *domain, *maildir)

	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("smtp-server: %v", err)
	}
}
