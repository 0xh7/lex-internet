package proxy

import (
	"net"
	"testing"
)

func TestIsBlockedIP(t *testing.T) {
	tests := []struct {
		name    string
		ip      net.IP
		blocked bool
	}{
		{name: "loopback", ip: net.IPv4(127, 0, 0, 1), blocked: true},
		{name: "private", ip: net.IPv4(10, 0, 0, 1), blocked: true},
		{name: "multicast", ip: net.IPv4(224, 0, 0, 1), blocked: true},
		{name: "broadcast", ip: net.IPv4bcast, blocked: true},
		{name: "public", ip: net.IPv4(1, 1, 1, 1), blocked: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isBlockedIP(tc.ip); got != tc.blocked {
				t.Fatalf("isBlockedIP(%v) = %v, want %v", tc.ip, got, tc.blocked)
			}
		})
	}
}
