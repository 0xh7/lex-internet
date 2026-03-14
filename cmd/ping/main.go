package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"math"
	"net"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"time"

	"github.com/0xh7/lex-internet/pkg/icmp"
)

func extractReplyTTL(raw []byte) (int, bool) {
	if len(raw) < 20 || raw[0]>>4 != 4 {
		return 0, false
	}
	ihl := int(raw[0]&0x0f) * 4
	if ihl < 20 || ihl > len(raw) {
		return 0, false
	}
	totalLen := int(binary.BigEndian.Uint16(raw[2:4]))
	if totalLen > 0 && totalLen < ihl {
		return 0, false
	}
	return int(raw[8]), true
}

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
			expectedSeq := uint16(seq & 0xffff)

			buf := make([]byte, 1500)
			deadline := sendTime.Add(*timeout)
			timedOut := true
			for {
				conn.SetReadDeadline(deadline)
				n, from, err := conn.ReadFromIP(buf)
				if err != nil {
					if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
						fmt.Printf("Request timeout for icmp_seq %d\n", seq)
					} else {
						fmt.Fprintf(os.Stderr, "ping: recv: %v\n", err)
					}
					break
				}

				reply, err := icmp.ParsePacket(buf[:n])
				if err != nil {
					continue
				}

				switch reply.Type {
				case icmp.TypeEchoReply:
					if reply.ID != id || reply.Seq != expectedSeq {
						continue
					}
					rtt := time.Since(sendTime)
					mu.Lock()
					received++
					ms := float64(rtt.Microseconds()) / 1000.0
					rtts = append(rtts, ms)
					mu.Unlock()
					ttlText := "?"
					if replyTTL, ok := extractReplyTTL(buf[:n]); ok {
						ttlText = strconv.Itoa(replyTTL)
					}
					fmt.Printf("%d bytes from %s: icmp_seq=%d ttl=%s time=%.3f ms\n",
						len(reply.Data)+8, from.IP, reply.Seq, ttlText, ms)
					timedOut = false
				case icmp.TypeDestUnreachable:
					fmt.Printf("From %s: Destination unreachable (code=%d)\n", from.IP, reply.Code)
					timedOut = false
				case icmp.TypeTimeExceeded:
					fmt.Printf("From %s: Time exceeded\n", from.IP)
					timedOut = false
				default:
					continue
				}

				if !timedOut {
					break
				}
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
