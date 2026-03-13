package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/0xh7/lex-internet/pkg/dhcp"
)

func main() {
	startIP := flag.String("start", "192.168.1.100", "start of IP pool range")
	endIP := flag.String("end", "192.168.1.200", "end of IP pool range")
	gateway := flag.String("gateway", "192.168.1.1", "default gateway")
	dns := flag.String("dns", "8.8.8.8", "DNS server")
	leaseTime := flag.Duration("lease-time", 24*time.Hour, "lease duration")
	_ = flag.String("interface", "", "network interface to bind to (unused on most platforms)")
	flag.Parse()

	pool := dhcp.Pool{
		Start:     net.ParseIP(*startIP).To4(),
		End:       net.ParseIP(*endIP).To4(),
		Subnet:    net.CIDRMask(24, 32),
		Gateway:   net.ParseIP(*gateway).To4(),
		DNS:       net.ParseIP(*dns).To4(),
		LeaseTime: *leaseTime,
	}

	if pool.Start == nil || pool.End == nil || pool.Gateway == nil || pool.DNS == nil {
		fmt.Fprintln(os.Stderr, "invalid IP address in arguments")
		os.Exit(1)
	}

	srv := dhcp.NewServer(":67", pool)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sig
		fmt.Println("\nactive leases:")
		for _, l := range srv.Leases() {
			fmt.Printf("  %s -> %s (expires %s)\n", l.MAC, l.IP, l.Expiry.Format(time.RFC3339))
		}
		os.Exit(0)
	}()

	log.Printf("dhcp-server: pool %s - %s, gateway %s, dns %s, lease %s",
		pool.Start, pool.End, pool.Gateway, pool.DNS, pool.LeaseTime)

	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("dhcp-server: %v", err)
	}
}
