package dns

import "testing"

func TestCompressionPointerAcceptsMax14BitOffset(t *testing.T) {
	ct := newCompressionTable()
	ct.offsets["example.com"] = 0x3fff

	got := ct.compressName("example.com", nil)
	if len(got) != 2 {
		t.Fatalf("compressed length = %d, want 2", len(got))
	}
	if got[0] != 0xff || got[1] != 0xff {
		t.Fatalf("compressed pointer = [%#x %#x], want [0xff 0xff]", got[0], got[1])
	}
}

func TestCompressionStoresSuffixAtMax14BitOffset(t *testing.T) {
	ct := newCompressionTable()
	buf := make([]byte, 0x3fff)

	ct.compressName("a.example", buf)
	if got := ct.offsets["a.example"]; got != 0x3fff {
		t.Fatalf("offset = %#x, want %#x", got, 0x3fff)
	}
}
