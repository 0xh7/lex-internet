package dns

import "testing"

func TestCacheDeepCopiesRecords(t *testing.T) {
	cache := NewCache(8)
	defer cache.Close()

	records := []ResourceRecord{{
		Name:     "example.com",
		Type:     TypeA,
		Class:    ClassIN,
		TTL:      60,
		RDLength: 4,
		RData:    []byte{1, 2, 3, 4},
	}}

	cache.Set("example.com", TypeA, records, 60)
	records[0].RData[0] = 9

	got, ok := cache.Get("example.com", TypeA)
	if !ok {
		t.Fatal("expected cache hit")
	}
	if got[0].RData[0] != 1 {
		t.Fatalf("cached rdata[0] = %d, want 1", got[0].RData[0])
	}

	got[0].RData[1] = 8
	again, ok := cache.Get("example.com", TypeA)
	if !ok {
		t.Fatal("expected second cache hit")
	}
	if again[0].RData[1] != 2 {
		t.Fatalf("cached rdata mutated through Get(): got %d, want 2", again[0].RData[1])
	}
}
