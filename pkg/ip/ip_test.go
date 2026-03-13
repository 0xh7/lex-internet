package ip

import (
	"net"
	"testing"
)

func TestPacketMarshalRequiresIPv4(t *testing.T) {
	p := &Packet{
		TTL:      64,
		Protocol: ProtocolTCP,
		DstIP:    net.IPv4(1, 1, 1, 1),
	}

	if _, err := p.Marshal(); err == nil {
		t.Fatal("expected missing source IPv4 address to fail")
	}
}

func TestPacketMarshalComputesIHLFromOptionsLength(t *testing.T) {
	p := &Packet{
		TTL:      64,
		Protocol: ProtocolUDP,
		SrcIP:    net.IPv4(10, 0, 0, 1),
		DstIP:    net.IPv4(10, 0, 0, 2),
		Options:  []byte{1, 2, 3, 4},
	}

	raw, err := p.Marshal()
	if err != nil {
		t.Fatalf("Marshal(): %v", err)
	}
	if got := raw[0] & 0x0f; got != 6 {
		t.Fatalf("IHL = %d, want 6", got)
	}
}

func TestPacketMarshalRejectsTooManyOptions(t *testing.T) {
	p := &Packet{
		TTL:      64,
		Protocol: ProtocolUDP,
		SrcIP:    net.IPv4(10, 0, 0, 1),
		DstIP:    net.IPv4(10, 0, 0, 2),
		Options:  make([]byte, 44),
	}

	if _, err := p.Marshal(); err == nil {
		t.Fatal("expected oversized IPv4 options to fail")
	}
}
