package probes

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/mbishflavien/mcp-xray/findings"
	"github.com/mbishflavien/mcp-xray/internal/probes/promptinjection"
	"github.com/mbishflavien/mcp-xray/probe"
)

// PromptInjection is a probe.ToolProbe: for each tool, it calls the tool
// once with a benign, valid-looking argument set (BaselineArgs, the same
// generator the rate-limit probe uses) and, only if that one call cleanly
// succeeds, inspects the response text for content shaped like an
// attempt to hijack whatever LLM reads it next - indirect, "tool
// poisoning" prompt injection.
//
// Unlike schema-fuzz/auth-bypass, this probe never sends an adversarial
// payload - only the tool's own benign baseline. That matters: since
// mcp-xray's own probe string is never what gets inspected here, any
// match this probe finds is something the server chose to say on its
// own, not an artifact of mcp-xray's own input being reflected back.
type PromptInjection struct {
	// CallTimeout bounds the one call this probe makes per tool. A call
	// that doesn't return within this window is treated as a hang
	// (probe.OutcomeTimeout).
	CallTimeout time.Duration
}

// NewPromptInjection returns a PromptInjection probe with a sensible
// default per-call timeout.
func NewPromptInjection() *PromptInjection {
	return &PromptInjection{CallTimeout: defaultCallTimeout}
}

// ID implements probe.Probe.
func (p *PromptInjection) ID() string { return "prompt-injection" }

// RunTool implements probe.ToolProbe.
func (p *PromptInjection) RunTool(ctx context.Context, tc probe.ToolContext) ([]findings.Finding, error) {
	schema, err := json.Marshal(tc.Tool.InputSchema)
	if err != nil {
		return nil, fmt.Errorf("marshal input schema for %q: %w", tc.Tool.Name, err)
	}

	args, err := BaselineArgs(ctx, tc.Tool.Name, schema)
	if err != nil {
		return nil, fmt.Errorf("generate baseline args for %q: %w", tc.Tool.Name, err)
	}

	timeout := p.CallTimeout
	if timeout <= 0 {
		timeout = defaultCallTimeout
	}

	callCtx, cancel := context.WithTimeout(ctx, timeout)
	result, callErr := tc.Caller.CallTool(callCtx, tc.Tool.Name, args)
	cancel()

	outcome := probe.Classify(result, callErr)
	if outcome != probe.OutcomeAcceptedInvalid {
		// No server-chosen output to inspect either way: a benign call
		// that didn't cleanly succeed (rejected, crashed, timed out,
		// errored internally, or blocked by the safety policy) is
		// schema-fuzz/auth-bypass/rate-limit's story to tell, not this
		// probe's.
		return nil, nil
	}

	text := textContent(result)
	matches := promptinjection.Detect(text)
	if len(matches) == 0 {
		return nil, nil
	}

	out := make([]findings.Finding, 0, len(matches))
	for _, m := range matches {
		out = append(out, findings.Finding{
			ProbeID:  p.ID(),
			Severity: severityForPromptInjectionKind(m.Kind),
			Kind:     m.Kind,
			Title:    fmt.Sprintf("%s: found in %q's output", m.Kind, tc.Tool.Name),
			Detail:   fmt.Sprintf("matched %q", m.Snippet),
			Target:   tc.Tool.Name,
			Evidence: evidenceFor(result, nil),
		})
	}
	return out, nil
}

// severityForPromptInjectionKind maps a promptinjection.Kind* constant to
// a Finding severity. role_impersonation and hidden_content are Critical:
// both have essentially no legitimate reason to appear in real tool
// output at all. instruction_override and exfiltration are High: still
// serious, but each carries a documented, if small, false-positive risk
// (see their doc comments in internal/probes/promptinjection).
func severityForPromptInjectionKind(kind string) findings.Severity {
	switch kind {
	case promptinjection.KindRoleImpersonation, promptinjection.KindHiddenContent:
		return findings.Critical
	case promptinjection.KindInstructionOverride, promptinjection.KindExfiltration:
		return findings.High
	default:
		return findings.Info
	}
}
