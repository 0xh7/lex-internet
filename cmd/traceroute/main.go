package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/0xh7/lex-internet/pkg/icmp"
)

func main() {
	maxHops := flag.Int("m", 30, "max number of hops")
	queries := flag.Int("q", 3, "number of queries per hop")
	timeout := flag.Duration("w", 3*time.Second, "timeout per probe")
	mode := flag.String("P", "icmp", "protocol: icmp or udp")
	flag.Parse()

	if flag.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "usage: traceroute [flags] host\n")
		os.Exit(1)
	}

	target := flag.Arg(0)
	dst, err := net.ResolveIPAddr("ip4", target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "traceroute: resolve %s: %v\n", target, err)
		os.Exit(1)
	}

	fmt.Printf("traceroute to %s (%s), %d hops max\n", target, dst.IP, *maxHops)

	id := uint16(os.Getpid() & 0xffff)
	seq := uint16(0)

	for ttl := 1; ttl <= *maxHops; ttl++ {
		fmt.Printf("%2d  ", ttl)
		lastAddr := ""
		reached := false

		for q := 0; q < *queries; q++ {
			var rtt time.Duration
			var from string
			var err error

			if *mode == "udp" {
				rtt, from, err = probeUDP(dst.IP, ttl, *timeout, 33434+ttl)
			} else {
				rtt, from, err = probeICMP(dst.IP, ttl, *timeout, id, seq)
				seq++
			}

			if err != nil {
				fmt.Printf(" *")
				continue
			}

			if from != lastAddr {
				if lastAddr != "" {
					fmt.Printf("\n    ")
				}
				names, _ := net.LookupAddr(from)
				if len(names) > 0 {
					fmt.Printf(" %s (%s)", names[0], from)
				} else {
					fmt.Printf(" %s", from)
				}
				lastAddr = from
			}

			fmt.Printf("  %.3f ms", float64(rtt.Microseconds())/1000.0)

			if from == dst.IP.String() {
				reached = true
			}
		}
		fmt.Println()

		if reached {
			break
		}
	}
}

func probeICMP(dst net.IP, ttl int, timeout time.Duration, id, seq uint16) (time.Duration, string, error) {
	conn, err := net.ListenIP("ip4:icmp", nil)
	if err != nil {
		return 0, "", err
	}
	defer conn.Close()

	raw := icmp.NewEchoRequest(id, seq, make([]byte, 32))
	pkt := raw.Marshal()

	sendConn, err := net.DialIP("ip4:icmp", nil, &net.IPAddr{IP: dst})
	if err != nil {
		return 0, "", err
	}
	defer sendConn.Close()

	if rawConn, err := sendConn.SyscallConn(); err == nil {
		rawConn.Control(func(fd uintptr) {
			setTTL(fd, ttl)
		})
	}

	start := time.Now()
	if _, err := sendConn.Write(pkt); err != nil {
		return 0, "", err
	}

	buf := make([]byte, 1500)
	conn.SetReadDeadline(time.Now().Add(timeout))
	for {
		n, from, err := conn.ReadFromIP(buf)
		if err != nil {
			return 0, "", err
		}
		elapsed := time.Since(start)

		if n < 1 {
			continue
		}

		reply, err := icmp.Parse(buf[:n])
		if err != nil {
			continue
		}

		switch reply.Type {
		case icmp.TypeEchoReply:
			if reply.ID == id && reply.Seq == seq {
				return elapsed, from.IP.String(), nil
			}
		case icmp.TypeTimeExceeded:
			return elapsed, from.IP.String(), nil
		case icmp.TypeDestUnreachable:
			return elapsed, from.IP.String(), nil
		}
	}
}

func probeUDP(dst net.IP, ttl int, timeout time.Duration, port int) (time.Duration, string, error) {
	listener, err := net.ListenIP("ip4:icmp", nil)
	if err != nil {
		return 0, "", err
	}
	defer listener.Close()

	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: dst, Port: port})
	if err != nil {
		return 0, "", err
	}
	defer conn.Close()

	rawConn, err := conn.SyscallConn()
	if err == nil {
		rawConn.Control(func(fd uintptr) {
			setTTL(fd, ttl)
		})
	}

	start := time.Now()
	if _, err := conn.Write([]byte("traceroute")); err != nil {
		return 0, "", err
	}

	buf := make([]byte, 1500)
	listener.SetReadDeadline(time.Now().Add(timeout))
	for {
		n, from, err := listener.ReadFromIP(buf)
		if err != nil {
			return 0, "", err
		}
		elapsed := time.Since(start)

		if n < 1 {
			continue
		}

		reply, err := icmp.Parse(buf[:n])
		if err != nil {
			continue
		}

		switch reply.Type {
		case icmp.TypeTimeExceeded, icmp.TypeDestUnreachable:
			return elapsed, from.IP.String(), nil
		}
	}
}
