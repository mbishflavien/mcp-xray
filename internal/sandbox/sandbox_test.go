package sandbox

import (
	"context"
	_ "embed"
	"testing"
	"time"
)

//go:embed testdata/echo.wasm
var echoWasm []byte

func TestRunEchoesStdinToStdout(t *testing.T) {
	out, err := Run(context.Background(), echoWasm, []byte("hello"), DefaultTimeout)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	if string(out) != "hello" {
		t.Errorf("Run() = %q, want %q", out, "hello")
	}
}

// TestRunRespectsTimeout confirms a module isn't given unbounded wall-clock
// time: an adversarial or buggy probe shouldn't be able to hang the scan
// forever. An already-expired timeout is a reliable way to exercise the
// "terminated by the deadline" path without a custom infinite-loop module.
func TestRunRespectsTimeout(t *testing.T) {
	_, err := Run(context.Background(), echoWasm, []byte("hello"), 1*time.Nanosecond)
	if err == nil {
		t.Error("Run() with an already-expired timeout: want an error, got nil")
	}
}

func TestRunRespectsParentContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Run(ctx, echoWasm, []byte("hello"), DefaultTimeout)
	if err == nil {
		t.Error("Run() with an already-cancelled parent context: want an error, got nil")
	}
}
