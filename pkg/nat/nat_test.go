package nat

import (
	"net"
	"testing"
)

func TestTranslateRejectsInvalidExternalIP(t *testing.T) {
	table := NewNATTable(net.ParseIP("::1"), [2]uint16{40000, 40010})

	ip, port := table.Translate(net.IPv4(10, 0, 0, 10), 1234, 6)
	if ip != nil || port != 0 {
		t.Fatalf("Translate() = (%v, %d), want (nil, 0)", ip, port)
	}
}
