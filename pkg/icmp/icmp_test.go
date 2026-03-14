package icmp

import "testing"

func TestParsePacketAcceptsRawICMP(t *testing.T) {
	msg := NewEchoRequest(0x1234, 0x5, []byte("abc"))
	raw := msg.Marshal()

	got, err := ParsePacket(raw)
	if err != nil {
		t.Fatalf("ParsePacket(raw): %v", err)
	}
	if got.Type != TypeEchoRequest {
		t.Fatalf("Type = %d, want %d", got.Type, TypeEchoRequest)
	}
	if got.ID != 0x1234 || got.Seq != 0x5 {
		t.Fatalf("ID/Seq = %#x/%#x, want %#x/%#x", got.ID, got.Seq, 0x1234, 0x5)
	}
}

func TestParsePacketAcceptsIPv4EncapsulatedICMP(t *testing.T) {
	msg := NewEchoRequest(0x2345, 0x6, []byte("xyz"))
	icmpRaw := msg.Marshal()

	ipHeader := []byte{
		0x45, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		64, 1, 0x00, 0x00,
		127, 0, 0, 1,
		127, 0, 0, 1,
	}
	raw := append(ipHeader, icmpRaw...)

	got, err := ParsePacket(raw)
	if err != nil {
		t.Fatalf("ParsePacket(ip+icmp): %v", err)
	}
	if got.Type != TypeEchoRequest {
		t.Fatalf("Type = %d, want %d", got.Type, TypeEchoRequest)
	}
	if got.ID != 0x2345 || got.Seq != 0x6 {
		t.Fatalf("ID/Seq = %#x/%#x, want %#x/%#x", got.ID, got.Seq, 0x2345, 0x6)
	}
}

func TestParsePacketRejectsIPv4NonICMP(t *testing.T) {
	raw := []byte{
		0x45, 0x00, 0x00, 0x1c,
		0x00, 0x00, 0x00, 0x00,
		64, 6, 0x00, 0x00,
		127, 0, 0, 1,
		127, 0, 0, 1,
		0, 1, 2, 3, 4, 5, 6, 7,
	}

	if _, err := ParsePacket(raw); err == nil {
		t.Fatal("ParsePacket() should reject IPv4 packets with non-ICMP protocol")
	}
}

func TestParsePacketUsesIPv4TotalLength(t *testing.T) {
	msg := NewEchoRequest(0x1111, 0x2222, []byte("extra-data"))
	icmpRaw := msg.Marshal()

	raw := []byte{
		0x45, 0x00, 0x00, 0x1c,
		0x00, 0x00, 0x00, 0x00,
		64, 1, 0x00, 0x00,
		127, 0, 0, 1,
		127, 0, 0, 1,
	}
	raw = append(raw, icmpRaw...)

	got, err := ParsePacket(raw)
	if err != nil {
		t.Fatalf("ParsePacket(): %v", err)
	}
	if got.ID != 0x1111 || got.Seq != 0x2222 {
		t.Fatalf("ID/Seq = %#x/%#x, want %#x/%#x", got.ID, got.Seq, 0x1111, 0x2222)
	}
	if len(got.Data) != 0 {
		t.Fatalf("data length = %d, want 0 (trimmed by IPv4 total length)", len(got.Data))
	}
}
