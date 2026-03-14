package http

import "testing"

func TestBasicAuthMatch(t *testing.T) {
	creds := map[string]string{
		"alice": "s3cr3t",
	}

	if !basicAuthMatch(creds, "alice", "s3cr3t") {
		t.Fatal("basicAuthMatch() = false, want true for valid credentials")
	}
	if basicAuthMatch(creds, "alice", "wrong") {
		t.Fatal("basicAuthMatch() = true, want false for invalid password")
	}
	if basicAuthMatch(creds, "bob", "s3cr3t") {
		t.Fatal("basicAuthMatch() = true, want false for unknown user")
	}
	if basicAuthMatch(creds, "bob", "") {
		t.Fatal("basicAuthMatch() = true, want false for unknown user with empty pass")
	}
}
