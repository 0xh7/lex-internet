package dns

import (
	"strings"
	"testing"
)

func TestEncodeNameCheckedRejectsLongLabel(t *testing.T) {
	label := strings.Repeat("a", 64)
	if _, err := encodeNameChecked(label + ".example.com"); err == nil {
		t.Fatal("encodeNameChecked() error = nil, want label length error")
	}
}

func TestMarshalRejectsLongQuestionLabel(t *testing.T) {
	label := strings.Repeat("a", 64)
	msg := NewQuery(1, label+".example.com", TypeA, ClassIN)
	if _, err := msg.Marshal(); err == nil {
		t.Fatal("Marshal() error = nil, want label length error")
	}
}
