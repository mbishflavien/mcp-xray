package main

import (
	"strings"
	"testing"
)

func TestRunRequiresEitherURLOrCommand(t *testing.T) {
	_, err := run([]string{"--"})
	if err == nil {
		t.Fatal("run() with neither -url nor a command: want an error, got nil")
	}
	if !strings.Contains(err.Error(), "no server command") {
		t.Errorf("error = %q, want it to mention a missing server command", err)
	}
}

func TestRunRejectsURLAndCommandTogether(t *testing.T) {
	_, err := run([]string{"-url", "http://localhost:1", "--", "echo", "hi"})
	if err == nil {
		t.Fatal("run() with both -url and a command: want an error, got nil")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("error = %q, want it to mention they're mutually exclusive", err)
	}
}

func TestRunRejectsMissingDoubleDash(t *testing.T) {
	_, err := run([]string{"-url", "http://localhost:1"})
	if err == nil {
		t.Fatal("run() with no -- at all: want an error, got nil")
	}
}

// TestRunRejectsBadURLScheme confirms a -url with an unsupported scheme
// fails before run() ever tries to connect, surfacing
// inspector.ConnectHTTP's own validation through the CLI.
func TestRunRejectsBadURLScheme(t *testing.T) {
	_, err := run([]string{"-url", "ftp://example.com", "--"})
	if err == nil {
		t.Fatal("run() with a non-HTTP -url scheme: want an error, got nil")
	}
	if !strings.Contains(err.Error(), "scheme") {
		t.Errorf("error = %q, want it to mention the unsupported scheme", err)
	}
}
