package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/0xh7/lex-internet/pkg/ftp"
)

func main() {
	listen := flag.String("listen", ":2121", "listen address")
	root := flag.String("root", ".", "root directory")
	user := flag.String("user", "", "username")
	pass := flag.String("pass", "", "password")
	anonymous := flag.Bool("anonymous", true, "allow anonymous access")
	flag.Parse()

	absRoot, err := filepath.Abs(*root)
	if err != nil {
		log.Fatal(err)
	}
	if err := os.MkdirAll(absRoot, 0755); err != nil {
		log.Fatal(err)
	}

	server := ftp.NewServer(*listen, absRoot)
	server.AllowAnonymous(*anonymous)
	if *user != "" || *pass != "" {
		server.SetAuth(*user, *pass)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		server.Close()
	}()

	log.Printf("ftp server serving %s on %s", absRoot, *listen)
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
