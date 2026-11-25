package scan

import (
	"context"
	"errors"
	"testing"

	"github.com/mbishflavien/mcp-xray/findings"
	"github.com/mbishflavien/mcp-xray/probe"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// fakeCaller records every call it actually receives, so tests can assert
// a blocked tool never reached it.
type fakeCaller struct {
	calls []string
}

func (f *fakeCaller) CallTool(_ context.Context, name string, _ map[string]any) (*mcp.CallToolResult, error) {
	f.calls = append(f.calls, name)
	return &mcp.CallToolResult{}, nil
}

// blockPolicy blocks every tool whose name is in blocked.
type blockPolicy struct {
	blocked map[string]bool
}

func (p *blockPolicy) Allow(tool *mcp.Tool) (bool, string) {
	if p.blocked[tool.Name] {
		return false, "blocked for test"
	}
	return true, ""
}

// fakeToolProbe calls its one tool once via the gated caller it's given,
// and reports a Finding for the Classify()'d outcome.
type fakeToolProbe struct {
	id      string
	wantErr error
}

func (p *fakeToolProbe) ID() string { return p.id }

func (p *fakeToolProbe) RunTool(ctx context.Context, tc probe.ToolContext) ([]findings.Finding, error) {
	result, err := tc.Caller.CallTool(ctx, tc.Tool.Name, nil)
	outcome := probe.Classify(result, err)
	finding := findings.Finding{ProbeID: p.id, Severity: outcome.Severity(), Title: outcome.String(), Target: tc.Tool.Name}
	return []findings.Finding{finding}, p.wantErr
}

// fakeServerProbe reports one fixed Finding, used to confirm ServerProbes
// run and their Findings are aggregated too.
type fakeServerProbe struct{ id string }

func (p *fakeServerProbe) ID() string { return p.id }

func (p *fakeServerProbe) RunServer(context.Context, probe.ServerContext) ([]findings.Finding, error) {
	return []findings.Finding{{ProbeID: p.id, Title: "server-wide"}}, nil
}

func testSnapshot() probe.Snapshot {
	return probe.Snapshot{
		Tools: []*mcp.Tool{
			{Name: "safe_tool"},
			{Name: "delete_all_records"},
		},
	}
}

func TestRunnerBlocksUnsafeTool(t *testing.T) {
	caller := &fakeCaller{}
	policy := &blockPolicy{blocked: map[string]bool{"delete_all_records": true}}
	runner := NewRunner([]probe.Probe{&fakeToolProbe{id: "fake"}}, Options{Policy: policy})

	found, err := runner.Run(context.Background(), caller, testSnapshot())
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	for _, name := range caller.calls {
		if name == "delete_all_records" {
			t.Fatal("the blocked tool was actually called")
		}
	}
	if len(caller.calls) != 1 || caller.calls[0] != "safe_tool" {
		t.Errorf("calls = %v, want exactly [safe_tool]", caller.calls)
	}

	var sawBlocked bool
	for _, f := range found {
		if f.Target == "delete_all_records" {
			sawBlocked = true
			if f.Title != probe.OutcomeSkippedUnsafe.String() {
				t.Errorf("blocked tool's finding title = %q, want %q", f.Title, probe.OutcomeSkippedUnsafe.String())
			}
		}
	}
	if !sawBlocked {
		t.Error("expected a finding for the blocked tool, got none")
	}
}

func TestRunnerAggregatesServerProbes(t *testing.T) {
	caller := &fakeCaller{}
	runner := NewRunner([]probe.Probe{&fakeServerProbe{id: "server-wide-probe"}}, Options{})

	found, err := runner.Run(context.Background(), caller, testSnapshot())
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	if len(found) != 1 || found[0].Title != "server-wide" {
		t.Errorf("found = %v, want one server-wide finding", found)
	}
}

func TestRunnerOneProbeErrorDoesNotSuppressOthers(t *testing.T) {
	caller := &fakeCaller{}
	runner := NewRunner([]probe.Probe{
		&fakeToolProbe{id: "broken", wantErr: errors.New("boom")},
		&fakeToolProbe{id: "healthy"},
	}, Options{})

	found, err := runner.Run(context.Background(), caller, testSnapshot())
	if err == nil {
		t.Fatal("expected the broken probe's error to surface")
	}

	var healthyCount int
	for _, f := range found {
		if f.ProbeID == "healthy" {
			healthyCount++
		}
	}
	if healthyCount != len(testSnapshot().Tools) {
		t.Errorf("healthy probe produced %d findings, want %d (one per tool)", healthyCount, len(testSnapshot().Tools))
	}
}
