package probes

import (
	"context"
	"testing"

	"github.com/mbishflavien/mcp-xray/findings"
	"github.com/mbishflavien/mcp-xray/probe"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func getAccountTool() *mcp.Tool {
	return &mcp.Tool{
		Name: "get_account",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"account_id": map[string]any{"type": "string"},
				"role":       map[string]any{"type": "string"},
			},
		},
	}
}

func TestAuthBypassRunToolAcceptedIsHigh(t *testing.T) {
	ctx := context.Background()
	caller := &stubCaller{
		call: func(context.Context, string, map[string]any) (*mcp.CallToolResult, error) {
			return &mcp.CallToolResult{IsError: false}, nil
		},
	}

	p := NewAuthBypass()
	out, err := p.RunTool(ctx, probe.ToolContext{Caller: caller, Tool: getAccountTool()})
	if err != nil {
		t.Fatalf("RunTool() error: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("expected findings when every bypass attempt is silently accepted")
	}
	for _, f := range out {
		if f.Severity != findings.High {
			t.Errorf("finding %q severity = %v, want High (accepted bypass attempt)", f.Title, f.Severity)
		}
		if f.ProbeID != "auth-bypass" {
			t.Errorf("finding ProbeID = %q, want auth-bypass", f.ProbeID)
		}
	}
}

func TestAuthBypassRunToolRejectedNoFindings(t *testing.T) {
	ctx := context.Background()
	caller := &stubCaller{
		call: func(context.Context, string, map[string]any) (*mcp.CallToolResult, error) {
			return &mcp.CallToolResult{IsError: true}, nil
		},
	}

	p := NewAuthBypass()
	out, err := p.RunTool(ctx, probe.ToolContext{Caller: caller, Tool: getAccountTool()})
	if err != nil {
		t.Fatalf("RunTool() error: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("expected no findings when every bypass attempt is correctly rejected, got %d", len(out))
	}
}

func TestAuthBypassRunToolNoMatchingFieldsMakesNoCalls(t *testing.T) {
	ctx := context.Background()
	var calls int
	caller := &stubCaller{
		call: func(context.Context, string, map[string]any) (*mcp.CallToolResult, error) {
			calls++
			return &mcp.CallToolResult{}, nil
		},
	}

	p := NewAuthBypass()
	out, err := p.RunTool(ctx, probe.ToolContext{Caller: caller, Tool: greetTool()})
	if err != nil {
		t.Fatalf("RunTool() error: %v", err)
	}
	if calls != 0 {
		t.Errorf("CallTool was invoked %d times, want 0 for a tool with no authorization-shaped fields", calls)
	}
	if len(out) != 0 {
		t.Errorf("got %d findings, want 0", len(out))
	}
}

func TestAuthBypassRunToolStopsAfterFirstCrash(t *testing.T) {
	ctx := context.Background()
	var calls int
	caller := &stubCaller{
		call: func(context.Context, string, map[string]any) (*mcp.CallToolResult, error) {
			calls++
			return nil, mcp.ErrConnectionClosed
		},
	}

	p := NewAuthBypass()
	out, err := p.RunTool(ctx, probe.ToolContext{Caller: caller, Tool: getAccountTool()})
	if err != nil {
		t.Fatalf("RunTool() error: %v", err)
	}

	// getAccountTool has two matching fields (account_id, role); both
	// would crash, but RunTool should stop calling once the connection is
	// known dead instead of generating one duplicate finding per
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
}
