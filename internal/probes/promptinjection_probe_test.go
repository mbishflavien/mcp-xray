package probes

import (
	"context"
	"testing"

	"github.com/mbishflavien/mcp-xray/probe"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestPromptInjectionID(t *testing.T) {
	if got := NewPromptInjection().ID(); got != "prompt-injection" {
		t.Errorf("ID() = %q, want %q", got, "prompt-injection")
	}
}

func TestPromptInjectionRunToolAcceptedProducesNoFindingYet(t *testing.T) {
	ctx := context.Background()
	caller := &stubCaller{
		call: func(context.Context, string, map[string]any) (*mcp.CallToolResult, error) {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: "Hi there, nice to meet you."}},
			}, nil
		},
	}

	p := NewPromptInjection()
	out, err := p.RunTool(ctx, probe.ToolContext{Caller: caller, Tool: greetTool()})
	if err != nil {
		t.Fatalf("RunTool() error: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("got %d findings, want 0 (Detect isn't wired up yet)", len(out))
	}
}

func TestPromptInjectionRunToolRejectedProducesNoFinding(t *testing.T) {
	ctx := context.Background()
	caller := &stubCaller{
		call: func(context.Context, string, map[string]any) (*mcp.CallToolResult, error) {
			return &mcp.CallToolResult{IsError: true}, nil
		},
	}

	p := NewPromptInjection()
	out, err := p.RunTool(ctx, probe.ToolContext{Caller: caller, Tool: greetTool()})
	if err != nil {
		t.Fatalf("RunTool() error: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("got %d findings, want 0: no output text to inspect on a rejected call", len(out))
	}
}

func TestPromptInjectionRunToolCrashProducesNoFinding(t *testing.T) {
	ctx := context.Background()
	caller := &stubCaller{
		call: func(context.Context, string, map[string]any) (*mcp.CallToolResult, error) {
			return nil, mcp.ErrConnectionClosed
		},
	}

	p := NewPromptInjection()
	out, err := p.RunTool(ctx, probe.ToolContext{Caller: caller, Tool: greetTool()})
	if err != nil {
		t.Fatalf("RunTool() error: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("got %d findings, want 0: no output text to inspect when the tool crashed", len(out))
	}
}

func TestPromptInjectionRunToolInternalErrorProducesNoFinding(t *testing.T) {
	ctx := context.Background()
	caller := &stubCaller{
		call: func(context.Context, string, map[string]any) (*mcp.CallToolResult, error) {
			return nil, &jsonrpc.Error{Code: jsonrpc.CodeInternalError, Message: "internal error"}
		},
	}

	p := NewPromptInjection()
	out, err := p.RunTool(ctx, probe.ToolContext{Caller: caller, Tool: greetTool()})
	if err != nil {
		t.Fatalf("RunTool() error: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("got %d findings, want 0: no output text to inspect on an internal error", len(out))
	}
}

func TestPromptInjectionRunToolBlockedProducesNoFinding(t *testing.T) {
	ctx := context.Background()
	caller := &stubCaller{
		call: func(context.Context, string, map[string]any) (*mcp.CallToolResult, error) {
			return nil, &probe.BlockedError{Tool: "greet", Reason: "test"}
		},
	}

	p := NewPromptInjection()
	out, err := p.RunTool(ctx, probe.ToolContext{Caller: caller, Tool: greetTool()})
	if err != nil {
		t.Fatalf("RunTool() error: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("got %d findings, want 0: a blocked tool was never actually called", len(out))
	}
}
