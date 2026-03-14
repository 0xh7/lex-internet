package dhcp

import (
	"net"
	"testing"
	"time"
)

func TestAllocateIPDoesNotLoopOnMaxUint32(t *testing.T) {
	server := NewServer(":67", Pool{
		Start:     net.IPv4(255, 255, 255, 255),
		End:       net.IPv4(255, 255, 255, 255),
		LeaseTime: time.Minute,
	})
	server.allocated["255.255.255.255"] = true

	if got := server.allocateIP(net.HardwareAddr{1, 2, 3, 4, 5, 6}); got != nil {
		t.Fatalf("allocateIP() = %v, want nil", got)
	}
}

func TestBuildReplyHandlesNilGatewayAndDNS(t *testing.T) {
	server := NewServer(":67", Pool{
		LeaseTime: time.Minute,
	})
	req := &Message{
		HType:  1,
		HLen:   6,
		XID:    42,
		Flags:  0,
		GIAddr: net.IPv4zero,
	}
	copy(req.CHAddr[:], []byte{1, 2, 3, 4, 5, 6})

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("buildReply panicked with nil gateway/dns: %v", r)
		}
	}()

	reply := server.buildReply(req, MsgOffer, net.IPv4(10, 0, 0, 10))
	if reply == nil {
		t.Fatal("buildReply() = nil, want non-nil reply")
	}
	if opt := reply.GetOption(OptServerID); opt != nil {
		t.Fatalf("unexpected server id option with nil gateway: %v", opt.Data)
	}
	if opt := reply.GetOption(OptRouter); opt != nil {
		t.Fatalf("unexpected router option with nil gateway: %v", opt.Data)
	}
	if opt := reply.GetOption(OptDNS); opt != nil {
		t.Fatalf("unexpected dns option with nil dns: %v", opt.Data)
	}
}
