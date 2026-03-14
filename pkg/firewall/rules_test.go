package firewall

import (
	"net"
	"testing"
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
