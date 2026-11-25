package probes

import (
	"context"
	"testing"

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

func TestSchemaFuzzRunToolCrash(t *testing.T) {
	ctx := context.Background()
	caller := &stubCaller{
		call: func(context.Context, string, map[string]any) (*mcp.CallToolResult, error) {
			return nil, mcp.ErrConnectionClosed
		},
	}

	p := NewSchemaFuzz()
	out, err := p.RunTool(ctx, probe.ToolContext{Caller: caller, Tool: greetTool()})
	if err != nil {
		t.Fatalf("RunTool() error: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("expected findings when every mutation crashes the connection")
	}
	for _, f := range out {
		if f.Severity != findings.High {
			t.Errorf("finding %q severity = %v, want High (crash)", f.Title, f.Severity)
		}
		if f.Evidence == "" {
			t.Error("a crash finding should carry the error as evidence")
		}
	}
}
