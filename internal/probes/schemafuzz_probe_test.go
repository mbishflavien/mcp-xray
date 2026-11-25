package probes

import (
	"context"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/mbishflavien/mcp-xray/findings"
	"github.com/mbishflavien/mcp-xray/probe"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// stubCaller is a probe.ToolCaller whose CallTool behavior is supplied by
// the test, so RunTool can be exercised without a real MCP session.
type stubCaller struct {
	call func(ctx context.Context, name string, args map[string]any) (*mcp.CallToolResult, error)
}

func (s *stubCaller) CallTool(ctx context.Context, name string, args map[string]any) (*mcp.CallToolResult, error) {
	return s.call(ctx, name, args)
}

func greetTool() *mcp.Tool {
	return &mcp.Tool{
		Name: "greet",
		InputSchema: map[string]any{
			"type":       "object",
			"properties": map[string]any{"name": map[string]any{"type": "string"}},
		},
	}
}

func TestSchemaFuzzRunToolAllAccepted(t *testing.T) {
	ctx := context.Background()
	caller := &stubCaller{
		call: func(context.Context, string, map[string]any) (*mcp.CallToolResult, error) {
			return &mcp.CallToolResult{IsError: false}, nil
		},
	}

	p := NewSchemaFuzz()
	out, err := p.RunTool(ctx, probe.ToolContext{Caller: caller, Tool: greetTool()})
	if err != nil {
		t.Fatalf("RunTool() error: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("expected findings when every mutation is silently accepted")
	}
	for _, f := range out {
		if f.Severity != findings.Low {
			t.Errorf("finding %q severity = %v, want Low (accepted-invalid)", f.Title, f.Severity)
		}
		if f.ProbeID != "schema-fuzz" {
			t.Errorf("finding ProbeID = %q, want schema-fuzz", f.ProbeID)
		}
	}
}

func TestSchemaFuzzRunToolAllRejected(t *testing.T) {
	ctx := context.Background()
	caller := &stubCaller{
		call: func(context.Context, string, map[string]any) (*mcp.CallToolResult, error) {
			return &mcp.CallToolResult{IsError: true}, nil
		},
	}

	p := NewSchemaFuzz()
	out, err := p.RunTool(ctx, probe.ToolContext{Caller: caller, Tool: greetTool()})
	if err != nil {
		t.Fatalf("RunTool() error: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("expected no findings when every mutation is correctly rejected, got %d", len(out))
	}
}

// TestSchemaFuzzRunToolCapsEvidenceLength confirms a tool that echoes an
// oversized response back (exactly what the oversized-string mutation
// asks it to do) doesn't make its Finding's Evidence grow without bound.
func TestSchemaFuzzRunToolCapsEvidenceLength(t *testing.T) {
	ctx := context.Background()
	huge := strings.Repeat("A", 1_000_000)
	caller := &stubCaller{
		call: func(context.Context, string, map[string]any) (*mcp.CallToolResult, error) {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: huge}},
			}, nil
		},
	}

	p := NewSchemaFuzz()
	out, err := p.RunTool(ctx, probe.ToolContext{Caller: caller, Tool: greetTool()})
	if err != nil {
		t.Fatalf("RunTool() error: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("expected findings")
	}
	for _, f := range out {
		if len(f.Evidence) > maxEvidenceLen+100 { // +100 for the truncation note itself
			t.Errorf("finding Evidence is %d bytes, want capped near %d", len(f.Evidence), maxEvidenceLen)
		}
	}
}

func TestTruncate(t *testing.T) {
	if got := truncate("short", 100); got != "short" {
		t.Errorf("truncate() of a short string changed it: %q", got)
	}

	long := strings.Repeat("x", 50)
	got := truncate(long, 10)
	if !strings.HasPrefix(got, strings.Repeat("x", 10)) {
		t.Errorf("truncate() didn't keep the first 10 bytes: %q", got)
	}
	if !strings.Contains(got, "truncated") {
		t.Errorf("truncate() of an oversized string should note it was truncated: %q", got)
	}

	// A multi-byte rune straddling the cut point must not produce
	// invalid UTF-8.
	multiByte := "a" + strings.Repeat("é", 20) // é is 2 bytes in UTF-8
	for cut := 1; cut < len(multiByte); cut++ {
		if got := truncate(multiByte, cut); !utf8.ValidString(got) {
			t.Fatalf("truncate(%q, %d) = %q, not valid UTF-8", multiByte, cut, got)
		}
	}
}

func TestSchemaFuzzRunToolStopsAfterFirstCrash(t *testing.T) {
	ctx := context.Background()
	var calls int
	caller := &stubCaller{
		call: func(context.Context, string, map[string]any) (*mcp.CallToolResult, error) {
			calls++
			return nil, mcp.ErrConnectionClosed
		},
	}

	p := NewSchemaFuzz()
	out, err := p.RunTool(ctx, probe.ToolContext{Caller: caller, Tool: greetTool()})
	if err != nil {
		t.Fatalf("RunTool() error: %v", err)
	}

	// greetTool has more than one string mutation; every one of them
	// would crash, but RunTool should stop calling once the connection
	// is known dead instead of generating one duplicate finding per
	// remaining mutation.
	if calls != 1 {
		t.Errorf("CallTool was invoked %d times, want exactly 1 (stop after the first crash)", calls)
	}
	if len(out) != 1 {
		t.Fatalf("got %d findings, want exactly 1", len(out))
	}
	if out[0].Severity != findings.High {
		t.Errorf("finding severity = %v, want High (crash)", out[0].Severity)
	}
	if out[0].Evidence == "" {
		t.Error("a crash finding should carry the error as evidence")
	}
}
