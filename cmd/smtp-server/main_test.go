package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMaildirHandlerWritesViaTmpThenPublishesToNew(t *testing.T) {
	root := t.TempDir()
	for _, sub := range []string{"tmp", "new", "cur"} {
		if err := os.MkdirAll(filepath.Join(root, sub), 0755); err != nil {
			t.Fatalf("MkdirAll(%s): %v", sub, err)
		}
	}

	handler := &maildirHandler{dir: root}
	if err := handler.HandleMessage("a@example.com", []string{"b@example.com"}, []byte("body")); err != nil {
		t.Fatalf("HandleMessage(): %v", err)
	}

	newEntries, err := os.ReadDir(filepath.Join(root, "new"))
	if err != nil {
		t.Fatalf("ReadDir(new): %v", err)
	}
	if len(newEntries) != 1 {
		t.Fatalf("new entries = %d, want 1", len(newEntries))
	}

	tmpEntries, err := os.ReadDir(filepath.Join(root, "tmp"))
	if err != nil {
		t.Fatalf("ReadDir(tmp): %v", err)
	}
	if len(tmpEntries) != 0 {
		t.Fatalf("tmp entries = %d, want 0", len(tmpEntries))
	}
}
