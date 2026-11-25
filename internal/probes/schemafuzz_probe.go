package probes

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/mbishflavien/mcp-xray/findings"
	"github.com/mbishflavien/mcp-xray/probe"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const defaultCallTimeout = 5 * time.Second

// SchemaFuzz is a probe.ToolProbe: for each tool it generates adversarial
// mutations from the tool's input schema (via the sandboxed schema-fuzz
// WASI probe) and actually calls the tool with each one, turning any
// non-healthy outcome into a Finding.
type SchemaFuzz struct {
	// CallTimeout bounds each individual tool call. A call that doesn't
	// return within this window is treated as a hang (probe.OutcomeTimeout).
	CallTimeout time.Duration
}

// NewSchemaFuzz returns a SchemaFuzz probe with a sensible default
// per-call timeout.
func NewSchemaFuzz() *SchemaFuzz {
	return &SchemaFuzz{CallTimeout: defaultCallTimeout}
}

// ID implements probe.Probe.
func (p *SchemaFuzz) ID() string { return "schema-fuzz" }

// RunTool implements probe.ToolProbe.
func (p *SchemaFuzz) RunTool(ctx context.Context, tc probe.ToolContext) ([]findings.Finding, error) {
	schema, err := json.Marshal(tc.Tool.InputSchema)
	if err != nil {
		return nil, fmt.Errorf("marshal input schema for %q: %w", tc.Tool.Name, err)
	}

	mutations, err := SchemaFuzzMutations(ctx, tc.Tool.Name, schema)
	if err != nil {
		return nil, fmt.Errorf("generate mutations for %q: %w", tc.Tool.Name, err)
	}

	timeout := p.CallTimeout
	if timeout <= 0 {
		timeout = defaultCallTimeout
	}

	var out []findings.Finding
	for _, m := range mutations {
		callCtx, cancel := context.WithTimeout(ctx, timeout)
		result, callErr := tc.Caller.CallTool(callCtx, tc.Tool.Name, m.Args)
		cancel()

		outcome := probe.Classify(result, callErr)
		if !outcome.Reportable() {
			continue
		}
		out = append(out, findings.Finding{
			ProbeID:  p.ID(),
			Severity: outcome.Severity(),
			Kind:     m.Kind,
			Title:    fmt.Sprintf("%s: %s", m.Kind, outcome),
			Detail:   m.Description,
			Target:   tc.Tool.Name,
			Evidence: evidenceFor(result, callErr),
		})
	}
	return out, nil
}

// evidenceFor extracts the most useful single piece of evidence for a
// Finding: the call error if there was one, otherwise the first text
// content in the result, otherwise nothing.
func evidenceFor(result *mcp.CallToolResult, err error) string {
	if err != nil {
		return err.Error()
	}
	if result == nil {
		return ""
	}
	for _, c := range result.Content {
		if text, ok := c.(*mcp.TextContent); ok {
			return text.Text
		}
	}
	return ""
}
