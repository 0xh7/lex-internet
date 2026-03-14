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

func TestEncodeNameCheckedRejectsEmptyLabel(t *testing.T) {
	if _, err := encodeNameChecked("a..example.com"); err == nil {
		t.Fatal("encodeNameChecked() error = nil, want empty-label error")
	}
}

func TestMarshalRejectsEmptyQuestionLabel(t *testing.T) {
	msg := NewQuery(1, "a..example.com", TypeA, ClassIN)
	if _, err := msg.Marshal(); err == nil {
		t.Fatal("Marshal() error = nil, want empty-label error")
	}
}
