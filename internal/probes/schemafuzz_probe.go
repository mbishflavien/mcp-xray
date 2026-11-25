package probes

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/mbishflavien/mcp-xray/findings"
	"github.com/mbishflavien/mcp-xray/probe"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const defaultCallTimeout = 5 * time.Second

// maxEvidenceLen caps how much of a tool's own response (or error text)
// gets copied into a Finding's Evidence. A malicious or buggy MCP server
// can return an arbitrarily large response - we've seen this ourselves
// with the oversized-string mutation, which asks for exactly that - and
// without a cap, a single Finding (and the report containing it) could
// grow to the size of whatever the server chose to send back.
const maxEvidenceLen = 2000

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
		if outcome == probe.OutcomeCrash {
			// The tool's process (or the connection to it) is dead. Every
			// remaining mutation against this same tool would just
			// rediscover the same crash, not a new one - stop here
			// instead of piling up duplicate findings.
			break
		}
	}
	return out, nil
}

// evidenceFor extracts the most useful single piece of evidence for a
// Finding: the call error if there was one, otherwise the first text
// content in the result, otherwise nothing. The result is capped at
// maxEvidenceLen.
func evidenceFor(result *mcp.CallToolResult, err error) string {
	if err != nil {
		return truncate(err.Error(), maxEvidenceLen)
	}
	if result == nil {
		return ""
	}
	for _, c := range result.Content {
		if text, ok := c.(*mcp.TextContent); ok {
			return truncate(text.Text, maxEvidenceLen)
		}
	}
	return ""
}

// truncate shortens s to at most maxLen bytes, cutting on a UTF-8 rune
// boundary so the result is never invalid UTF-8, and notes how much was
// cut.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	cut := s[:maxLen]
	for len(cut) > 0 && !utf8.ValidString(cut) {
		cut = cut[:len(cut)-1]
	}
	return fmt.Sprintf("%s ... (truncated, %d bytes total)", cut, len(s))
}
