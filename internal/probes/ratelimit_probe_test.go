package probes

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mbishflavien/mcp-xray/findings"
	"github.com/mbishflavien/mcp-xray/probe"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestRateLimitRunServerNoThrottleSignalFindsAbsent(t *testing.T) {
	ctx := context.Background()
	caller := &stubCaller{
		call: func(context.Context, string, map[string]any) (*mcp.CallToolResult, error) {
			return &mcp.CallToolResult{IsError: false}, nil
		},
	}

	p := NewRateLimit()
	out, err := p.RunServer(ctx, probe.ServerContext{
		Caller:   caller,
		Snapshot: probe.Snapshot{Tools: []*mcp.Tool{greetTool()}},
	})
	if err != nil {
		t.Fatalf("RunServer() error: %v", err)
	}
	if len(out) != 1 || out[0].Kind != KindAbsent || out[0].Severity != findings.Low {
		t.Errorf("findings = %+v, want exactly one Low %s", out, KindAbsent)
	}
}

func TestRateLimitRunServerLatencyGrowthSuppressesAbsentFinding(t *testing.T) {
	ctx := context.Background()
	var calls int
	caller := &stubCaller{
		call: func(context.Context, string, map[string]any) (*mcp.CallToolResult, error) {
			calls++
			if calls > 2 {
				time.Sleep(80 * time.Millisecond)
			}
			return &mcp.CallToolResult{IsError: false}, nil
		},
	}

	p := NewRateLimit()
	out, err := p.RunServer(ctx, probe.ServerContext{
		Caller:   caller,
		Snapshot: probe.Snapshot{Tools: []*mcp.Tool{greetTool()}},
	})
	if err != nil {
		t.Fatalf("RunServer() error: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("got %d findings, want 0: growing latency is itself a (soft) throttling signal", len(out))
	}
}

func TestRateLimitRunServerTooFewSamplesStillFindsAbsent(t *testing.T) {
	ctx := context.Background()
	caller := &stubCaller{
		call: func(context.Context, string, map[string]any) (*mcp.CallToolResult, error) {
			return &mcp.CallToolResult{IsError: false}, nil
		},
	}

	p := NewRateLimit()
	p.BurstSize = 2 // below minLatencySamples: too little data either way
	out, err := p.RunServer(ctx, probe.ServerContext{
		Caller:   caller,
		Snapshot: probe.Snapshot{Tools: []*mcp.Tool{greetTool()}},
	})
	if err != nil {
		t.Fatalf("RunServer() error: %v", err)
	}
	if len(out) != 1 || out[0].Kind != KindAbsent {
		t.Errorf("findings = %+v, want exactly one %s (not enough samples to detect degradation, so no signal is assumed)", out, KindAbsent)
	}
}

func TestRateLimitRunServerStopsOnCrash(t *testing.T) {
	ctx := context.Background()
	var calls int
	caller := &stubCaller{
		call: func(context.Context, string, map[string]any) (*mcp.CallToolResult, error) {
			calls++
			if calls < 3 {
				return &mcp.CallToolResult{IsError: false}, nil
			}
			return nil, mcp.ErrConnectionClosed
		},
	}

	p := NewRateLimit()
	out, err := p.RunServer(ctx, probe.ServerContext{
		Caller:   caller,
		Snapshot: probe.Snapshot{Tools: []*mcp.Tool{greetTool()}},
	})
	if err != nil {
		t.Fatalf("RunServer() error: %v", err)
	}
	if calls != 3 {
		t.Errorf("CallTool was invoked %d times, want exactly 3 (stop at the crash)", calls)
	}
	if len(out) != 1 {
		t.Fatalf("got %d findings, want exactly 1", len(out))
	}
	if out[0].Kind != KindDoS || out[0].Severity != findings.High {
		t.Errorf("finding = %+v, want High %s", out[0], KindDoS)
	}
}

func TestRateLimitRunServerFirstCallCrashProducesNoFinding(t *testing.T) {
	ctx := context.Background()
	var calls int
	caller := &stubCaller{
		call: func(context.Context, string, map[string]any) (*mcp.CallToolResult, error) {
			calls++
			return nil, mcp.ErrConnectionClosed
		},
	}

	p := NewRateLimit()
	out, err := p.RunServer(ctx, probe.ServerContext{
		Caller:   caller,
		Snapshot: probe.Snapshot{Tools: []*mcp.Tool{greetTool()}},
	})
	if err != nil {
		t.Fatalf("RunServer() error: %v", err)
	}
	if calls != 1 {
		t.Errorf("CallTool was invoked %d times, want exactly 1 (not attributable to the burst)", calls)
	}
	if len(out) != 0 {
		t.Errorf("got %d findings, want 0: a tool already broken on the first call isn't a rate-limit finding", len(out))
	}
}

func TestRateLimitRunServerSkipsBlockedTool(t *testing.T) {
	ctx := context.Background()
	var calls int
	caller := &stubCaller{
		call: func(context.Context, string, map[string]any) (*mcp.CallToolResult, error) {
			calls++
			return nil, &probe.BlockedError{Tool: "greet", Reason: "test"}
		},
	}

	p := NewRateLimit()
	out, err := p.RunServer(ctx, probe.ServerContext{
		Caller:   caller,
		Snapshot: probe.Snapshot{Tools: []*mcp.Tool{greetTool()}},
	})
	if err != nil {
		t.Fatalf("RunServer() error: %v", err)
	}
	if calls != 1 {
		t.Errorf("CallTool was invoked %d times, want exactly 1 (don't waste the burst on an obviously-blocked tool)", calls)
	}
	if len(out) != 1 || out[0].Kind != KindSkipped || out[0].Severity != findings.Info {
		t.Errorf("findings = %+v, want exactly one Info %s", out, KindSkipped)
	}
}

// TestRateLimitRunServerBlockedToolCostsExactlyOneCallRegardlessOfBurstSize
// pins down a guarantee that matters for safety, not just efficiency: a
// tool the safety policy blocks is never hammered BurstSize times just
// because this probe doesn't know yet that it's blocked. A large
// BurstSize makes the point sharply - if this ever regressed to calling
// the real tool once per burst slot, this test would catch it even though
// TestRateLimitRunServerSkipsBlockedTool (at the default BurstSize) might
// not visibly differ by much.
func TestRateLimitRunServerBlockedToolCostsExactlyOneCallRegardlessOfBurstSize(t *testing.T) {
	ctx := context.Background()
	var calls int
	caller := &stubCaller{
		call: func(context.Context, string, map[string]any) (*mcp.CallToolResult, error) {
			calls++
			return nil, &probe.BlockedError{Tool: "greet", Reason: "test"}
		},
	}

	p := NewRateLimit()
	p.BurstSize = 100
	out, err := p.RunServer(ctx, probe.ServerContext{
		Caller:   caller,
		Snapshot: probe.Snapshot{Tools: []*mcp.Tool{greetTool()}},
	})
	if err != nil {
		t.Fatalf("RunServer() error: %v", err)
	}
	if calls != 1 {
		t.Errorf("CallTool was invoked %d times with BurstSize=100, want exactly 1", calls)
	}
	if len(out) != 1 || out[0].Kind != KindSkipped {
		t.Errorf("findings = %+v, want exactly one %s", out, KindSkipped)
	}
}

func TestRateLimitRunServerRejectedProducesNoFinding(t *testing.T) {
	ctx := context.Background()
	caller := &stubCaller{
		call: func(context.Context, string, map[string]any) (*mcp.CallToolResult, error) {
			return &mcp.CallToolResult{IsError: true}, nil
		},
	}

	p := NewRateLimit()
	out, err := p.RunServer(ctx, probe.ServerContext{
		Caller:   caller,
		Snapshot: probe.Snapshot{Tools: []*mcp.Tool{greetTool()}},
	})
	if err != nil {
		t.Fatalf("RunServer() error: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("got %d findings, want 0: a rejected baseline call isn't a rate-limit finding either way", len(out))
	}
}

func TestRateLimitRunServerInternalErrorReportedOnce(t *testing.T) {
	ctx := context.Background()
	var calls int
	caller := &stubCaller{
		call: func(context.Context, string, map[string]any) (*mcp.CallToolResult, error) {
			calls++
			if calls == 1 {
				return &mcp.CallToolResult{IsError: false}, nil
			}
			return nil, &jsonrpc.Error{Code: jsonrpc.CodeInternalError, Message: "internal error"}
		},
	}

	p := NewRateLimit()
	p.BurstSize = 4
	out, err := p.RunServer(ctx, probe.ServerContext{
		Caller:   caller,
		Snapshot: probe.Snapshot{Tools: []*mcp.Tool{greetTool()}},
	})
	if err != nil {
		t.Fatalf("RunServer() error: %v", err)
	}
	if calls != 4 {
		t.Errorf("CallTool was invoked %d times, want exactly 4 (an internal error doesn't stop the burst)", calls)
	}

	var internalErrorFindings int
	for _, f := range out {
		if f.Kind == KindInternalError {
			internalErrorFindings++
		}
	}
	if internalErrorFindings != 1 {
		t.Errorf("got %d %s findings, want exactly 1 (reported once, not once per occurrence)", internalErrorFindings, KindInternalError)
	}
}

func TestRateLimitRunServerRespectsBurstSizeAndCallTimeout(t *testing.T) {
	p := NewRateLimit()
	if p.BurstSize != defaultBurstSize {
		t.Errorf("default BurstSize = %d, want %d", p.BurstSize, defaultBurstSize)
	}
	if p.CallTimeout != defaultCallTimeout {
		t.Errorf("default CallTimeout = %v, want %v", p.CallTimeout, defaultCallTimeout)
	}
	if p.MaxDuration != defaultMaxDuration {
		t.Errorf("default MaxDuration = %v, want %v", p.MaxDuration, defaultMaxDuration)
	}
}

// TestRateLimitRunServerStopsStartingNewToolsPastMaxDuration confirms the
// whole-probe wall-clock ceiling actually bounds how many tools get a
// burst, rather than just existing as an unused field. A burst already in
// progress still finishes - only *starting the next tool* is what gets
// skipped.
func TestRateLimitRunServerStopsStartingNewToolsPastMaxDuration(t *testing.T) {
	ctx := context.Background()
	var calls int
	caller := &stubCaller{
		call: func(context.Context, string, map[string]any) (*mcp.CallToolResult, error) {
			calls++
			time.Sleep(20 * time.Millisecond)
			return &mcp.CallToolResult{IsError: false}, nil
		},
	}

	p := NewRateLimit()
	p.MaxDuration = 10 * time.Millisecond // tiny: the first tool's burst alone exceeds it
	tools := []*mcp.Tool{greetTool(), greetTool(), greetTool()}
	tools[1].Name, tools[2].Name = "tool-two", "tool-three"

	out, err := p.RunServer(ctx, probe.ServerContext{
		Caller:   caller,
		Snapshot: probe.Snapshot{Tools: tools},
	})
	if err != nil {
		t.Fatalf("RunServer() error: %v", err)
	}

	// The first tool's burst (BurstSize calls) still runs to completion -
	// only the ceiling-check *before starting the next tool* stops it.
	if calls != p.BurstSize {
		t.Errorf("CallTool was invoked %d times, want exactly %d (one tool's whole burst, no more)", calls, p.BurstSize)
	}
	if len(out) != 1 {
		t.Errorf("got %d findings, want exactly 1 (only the first tool was ever probed)", len(out))
	}
}

// TestRateLimitRunServerStopsImmediatelyOnContextCancellation confirms
// canceling the scan (e.g. Ctrl-C) stops a burst right away instead of
// grinding through its remaining calls, and doesn't get misreported as a
// rate-limit finding.
func TestRateLimitRunServerStopsImmediatelyOnContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var calls int
	caller := &stubCaller{
		call: func(context.Context, string, map[string]any) (*mcp.CallToolResult, error) {
			calls++
			if calls == 2 {
				cancel() // simulate the scan being canceled mid-burst
			}
			return &mcp.CallToolResult{IsError: false}, nil
		},
	}

	p := NewRateLimit()
	out, err := p.RunServer(ctx, probe.ServerContext{
		Caller:   caller,
		Snapshot: probe.Snapshot{Tools: []*mcp.Tool{greetTool()}},
	})
	if err != nil {
		t.Fatalf("RunServer() error: %v", err)
	}
	if calls != 2 {
		t.Errorf("CallTool was invoked %d times, want exactly 2 (stop immediately once canceled)", calls)
	}
	if len(out) != 0 {
		t.Errorf("got %d findings, want 0: a scan cancellation isn't a rate-limit finding", len(out))
	}
}

// TestRateLimitRunServerCapsEvidenceLengthOnDoSFinding confirms a tool
// that fails with an oversized error message (the same kind of thing a
// struggling, resource-exhausted process might emit) doesn't make the
// resulting Finding's Evidence grow without bound - the same cap every
// other probe's findings already get via evidenceFor/truncate, reused
// here rather than reimplemented.
func TestRateLimitRunServerCapsEvidenceLengthOnDoSFinding(t *testing.T) {
	ctx := context.Background()
	huge := strings.Repeat("A", 1_000_000)
	var calls int
	caller := &stubCaller{
		call: func(context.Context, string, map[string]any) (*mcp.CallToolResult, error) {
			calls++
			if calls == 1 {
				return &mcp.CallToolResult{IsError: false}, nil
			}
			return nil, errors.New(huge)
		},
	}

	p := NewRateLimit()
	out, err := p.RunServer(ctx, probe.ServerContext{
		Caller:   caller,
		Snapshot: probe.Snapshot{Tools: []*mcp.Tool{greetTool()}},
	})
	if err != nil {
		t.Fatalf("RunServer() error: %v", err)
	}
	if len(out) != 1 || out[0].Kind != KindDoS {
		t.Fatalf("findings = %+v, want exactly one %s", out, KindDoS)
	}
	if len(out[0].Evidence) > maxEvidenceLen+100 { // +100 for the truncation note itself
		t.Errorf("Evidence is %d bytes, want capped near %d", len(out[0].Evidence), maxEvidenceLen)
	}
}

func TestRateLimitID(t *testing.T) {
	if got := NewRateLimit().ID(); got != "rate-limit" {
		t.Errorf("ID() = %q, want %q", got, "rate-limit")
	}
}
