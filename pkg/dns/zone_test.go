package dns

import (
	"bytes"
	"net"
	"testing"
)

func TestQualifyAppendsOriginForBareName(t *testing.T) {
	got := qualify("app", "example.com")
	if got != "app.example.com" {
		t.Fatalf("qualify() = %q, want %q", got, "app.example.com")
	}
}

func TestParseZoneLineNumericOwnerNameIsNotTTL(t *testing.T) {
	rr, name, err := parseZoneLine("1 IN PTR host", "2", "example.com", 3600)
	if err != nil {
		t.Fatalf("parseZoneLine(): %v", err)
	}
	if name != "1" {
		t.Fatalf("name = %q, want %q", name, "1")
	}
	if rr.TTL != 3600 {
		t.Fatalf("ttl = %d, want %d", rr.TTL, 3600)
	}
	if rr.Type != TypePTR {
		t.Fatalf("type = %d, want %d", rr.Type, TypePTR)
	}
	want := encodeName("host.example.com")
	if !bytes.Equal(rr.RData, want) {
		t.Fatalf("rdata = %v, want %v", rr.RData, want)
	}
}

func TestParseZoneLineLeadingTTLWithOmittedOwner(t *testing.T) {
	rr, name, err := parseZoneLine(" 300 IN A 192.0.2.10", "www", "example.com", 60)
	if err != nil {
		t.Fatalf("parseZoneLine(): %v", err)
	}
	if name != "www" {
		t.Fatalf("name = %q, want %q", name, "www")
	}
	if rr.TTL != 300 {
		t.Fatalf("ttl = %d, want %d", rr.TTL, 300)
	}
	if got := net.IP(rr.RData).String(); got != "192.0.2.10" {
		t.Fatalf("rdata ip = %q, want %q", got, "192.0.2.10")
	}
}
