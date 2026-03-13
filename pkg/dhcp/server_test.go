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
