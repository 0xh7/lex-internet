package main

import (
	"flag"
	"fmt"
	"math"
	"net"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/0xh7/lex-internet/pkg/icmp"
)

func main() {
	count := flag.Int("c", 0, "number of pings (0 = unlimited)")
	interval := flag.Duration("i", time.Second, "interval between pings")
	ttl := flag.Int("t", 64, "time to live")
	size := flag.Int("s", 56, "payload size in bytes")
	timeout := flag.Duration("W", 2*time.Second, "timeout for each reply")
	flag.Parse()

	if flag.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "usage: ping [flags] host\n")
		os.Exit(1)
	}

	target := flag.Arg(0)
	addrs, err := net.ResolveIPAddr("ip4", target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ping: %v\n", err)
		os.Exit(1)
	}

	conn, err := net.DialIP("ip4:icmp", nil, addrs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ping: %v (try running as root/admin)\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	rawConn, err := conn.SyscallConn()
	if err == nil {
		rawConn.Control(func(fd uintptr) {
			setTTL(fd, *ttl)
		})
	}

	fmt.Printf("PING %s (%s): %d data bytes\n", target, addrs.IP, *size)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)

	id := uint16(os.Getpid() & 0xffff)

	var mu sync.Mutex
	var sent, received int
	var rtts []float64

	done := make(chan struct{})
	go func() {
		defer close(done)
		var seq int
		for {
			if *count > 0 && seq >= *count {
				return
			}

			payload := make([]byte, *size)
			for i := range payload {
				payload[i] = byte(i & 0xff)
			}

			msg := icmp.NewEchoRequest(id, uint16(seq&0xffff), payload)
			raw := msg.Marshal()

			conn.SetWriteDeadline(time.Now().Add(time.Second))
			_, err := conn.Write(raw)
			if err != nil {
				fmt.Fprintf(os.Stderr, "ping: send: %v\n", err)
				seq++
				mu.Lock()
				sent++
				mu.Unlock()
				time.Sleep(*interval)
				continue
			}
			mu.Lock()
			sent++
			mu.Unlock()
			sendTime := time.Now()

			buf := make([]byte, 1500)
			conn.SetReadDeadline(time.Now().Add(*timeout))
			n, from, err := conn.ReadFromIP(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					fmt.Printf("Request timeout for icmp_seq %d\n", seq)
				} else {
					fmt.Fprintf(os.Stderr, "ping: recv: %v\n", err)
				}
				seq++
				time.Sleep(*interval)
				continue
			}

			rtt := time.Since(sendTime)
			reply, err := icmp.Parse(buf[:n])
			if err != nil {
				fmt.Fprintf(os.Stderr, "ping: parse: %v\n", err)
				seq++
				time.Sleep(*interval)
				continue
			}

			switch reply.Type {
			case icmp.TypeEchoReply:
				if reply.ID != id {
					seq++
					continue
				}
				mu.Lock()
				received++
				ms := float64(rtt.Microseconds()) / 1000.0
				rtts = append(rtts, ms)
				mu.Unlock()
				fmt.Printf("%d bytes from %s: icmp_seq=%d ttl=%d time=%.3f ms\n",
					n, from.IP, reply.Seq, *ttl, ms)
			case icmp.TypeDestUnreachable:
				fmt.Printf("From %s: Destination unreachable (code=%d)\n", from.IP, reply.Code)
			case icmp.TypeTimeExceeded:
				fmt.Printf("From %s: Time exceeded\n", from.IP)
			default:
				fmt.Printf("From %s: unexpected ICMP type=%d code=%d\n", from.IP, reply.Type, reply.Code)
			}

			seq++
			if *count > 0 && seq >= *count {
				return
			}
			time.Sleep(*interval)
		}
	}()

	select {
	case <-sig:
	case <-done:
	}

	mu.Lock()
	finalSent := sent
	finalReceived := received
	finalRtts := make([]float64, len(rtts))
	copy(finalRtts, rtts)
	mu.Unlock()

	fmt.Printf("\n--- %s ping statistics ---\n", target)
	loss := 0.0
	if finalSent > 0 {
		loss = float64(finalSent-finalReceived) / float64(finalSent) * 100
	}
	fmt.Printf("%d packets transmitted, %d received, %.1f%% packet loss\n", finalSent, finalReceived, loss)

	if len(finalRtts) > 0 {
		min, max, sum := finalRtts[0], finalRtts[0], 0.0
		for _, r := range finalRtts {
			sum += r
			if r < min {
				min = r
			}
			if r > max {
				max = r
			}
		}
		avg := sum / float64(len(finalRtts))
		var variance float64
		for _, r := range finalRtts {
			d := r - avg
			variance += d * d
		}
		stddev := math.Sqrt(variance / float64(len(finalRtts)))
		fmt.Printf("rtt min/avg/max/stddev = %.3f/%.3f/%.3f/%.3f ms\n", min, avg, max, stddev)
	}
}
