package firewall

import (
	"bytes"
	"encoding/binary"
	"log"
	"net"
	"strings"
	"testing"
	"time"
)

func TestInsertRuleNegativeIndexInsertsAtFront(t *testing.T) {
	rs := NewRuleSet()
	rs.AddRule(Rule{Action: Allow, Protocol: "tcp", Direction: Both})
	rs.InsertRule(-1, Rule{Action: Deny, Protocol: "udp", Direction: Both})

	if rs.Len() != 2 {
		t.Fatalf("Len() = %d, want 2", rs.Len())
	}
	if got := rs.rules[0].Action; got != Deny {
		t.Fatalf("first rule action = %v, want %v", got, Deny)
	}
}

func TestEngineProcessHandlesNilIPs(t *testing.T) {
	rs := NewRuleSet()
	rs.AddRule(Rule{Action: Allow, Protocol: "*", Direction: Both})
	e := NewEngine(rs)
	defer e.Close()

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Process panicked with nil IPs: %v", r)
		}
	}()

	if ok := e.Process(PacketInfo{Protocol: "tcp", Direction: Inbound}); !ok {
		t.Fatal("expected packet with nil IPs to be processed without panic")
	}
}

func TestMakeKeyDistinguishesNilFromIPv6Zero(t *testing.T) {
	e := NewEngine(NewRuleSet())
	defer e.Close()

	nilKey := e.makeKey(PacketInfo{
		Protocol:  "tcp",
		Direction: Inbound,
	})
	zeroKey := e.makeKey(PacketInfo{
		SrcIP:     net.IPv6zero,
		DstIP:     net.IPv6zero,
		Protocol:  "tcp",
		Direction: Inbound,
	})

	if nilKey == zeroKey {
		t.Fatal("nil IP key collides with IPv6 zero key")
	}
}

func TestTrackConnLogsWhenTableIsFull(t *testing.T) {
	e := NewEngine(NewRuleSet())
	defer e.Close()

	var out bytes.Buffer
	e.SetLogger(log.New(&out, "", 0))

	now := time.Now()
	for i := 0; i < maxConnTableSize; i++ {
		var key connKey
		binary.BigEndian.PutUint32(key.srcIP[:4], uint32(i+1))
		binary.BigEndian.PutUint32(key.dstIP[:4], uint32(i+2))
		key.srcSet = true
		key.dstSet = true
		key.srcPort = 1000
		key.dstPort = 2000
		key.proto = "tcp"
		e.connTable[key] = &connEntry{state: stateEstablished, lastSeen: now}
	}

	e.trackConn(PacketInfo{
		SrcIP:    net.IPv4(192, 0, 2, 1),
		DstIP:    net.IPv4(198, 51, 100, 1),
		SrcPort:  12345,
		DstPort:  80,
		Protocol: "tcp",
	})

	if !strings.Contains(out.String(), "connection table full") {
		t.Fatalf("log = %q, want connection-table-full warning", out.String())
	}
}
