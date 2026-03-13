package smtp

import (
	"strings"
	"testing"
)

func TestEmailMarshalSkipsDuplicateMessageID(t *testing.T) {
	email := &Email{
		MessageID: "<one@example.com>",
		Headers: map[string]string{
			"Message-ID": "<two@example.com>",
		},
	}

	raw := string(email.Marshal())
	if count := strings.Count(raw, "Message-ID:"); count != 1 {
		t.Fatalf("Message-ID header count = %d, want 1", count)
	}
}
