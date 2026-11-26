package probes

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/mbishflavien/mcp-xray/findings"
	"github.com/mbishflavien/mcp-xray/probe"
)

// AuthBypass is a probe.ToolProbe: for each tool whose input schema has a
// field shaped like an identity, a privilege, or a credential (see
// internal/probes/authbypass), it calls the tool with a forged value for
// that field and turns a silently-accepted call into a Finding.
//
// Severity here is inverted from SchemaFuzz's: there, a mutation the server
// silently accepts is a Low-severity correctness smell. Here, a
// silently-accepted bypass attempt is the entire point of the probe, so it
// is High - see severityFor below.
type AuthBypass struct {
	// CallTimeout bounds each individual tool call. A call that doesn't
	// return within this window is treated as a hang (probe.OutcomeTimeout).
	CallTimeout time.Duration
}

// NewAuthBypass returns an AuthBypass probe with a sensible default
// per-call timeout.
func NewAuthBypass() *AuthBypass {
	return &AuthBypass{CallTimeout: defaultCallTimeout}
}

// ID implements probe.Probe.
func (p *AuthBypass) ID() string { return "auth-bypass" }

// RunTool implements probe.ToolProbe.
func (p *AuthBypass) RunTool(ctx context.Context, tc probe.ToolContext) ([]findings.Finding, error) {
	schema, err := json.Marshal(tc.Tool.InputSchema)
	if err != nil {
		return nil, fmt.Errorf("marshal input schema for %q: %w", tc.Tool.Name, err)
	}

	mutations, err := AuthBypassMutations(ctx, tc.Tool.Name, schema)
	if err != nil {
		return nil, fmt.Errorf("generate auth-bypass mutations for %q: %w", tc.Tool.Name, err)
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
			Severity: severityFor(outcome),
			Kind:     m.Kind,
			Title:    fmt.Sprintf("%s: %s", m.Kind, outcome),
			Detail:   m.Description,
			Target:   tc.Tool.Name,
			Evidence: evidenceFor(result, callErr),
		})
		if outcome == probe.OutcomeCrash {
			// The tool's process (or the connection to it) is dead. Every
			// remaining mutation against this same tool would just
			// rediscover the same crash, not a new one.
			break
		}
	}
	return out, nil
}

// severityFor maps an Outcome to a Finding severity for the auth-bypass
// probe specifically. It does not use Outcome.Severity(): that mapping
// treats an accepted mutation as a Low-severity correctness smell, which is
// right for SchemaFuzz's garbage-data mutations but wrong here, where an
// accepted mutation means a forged identity, privilege, or credential value
// was honored instead of rejected - the exact thing this probe exists to
// catch.
func severityFor(o probe.Outcome) findings.Severity {
	switch o {
	case probe.OutcomeAcceptedInvalid:
		return findings.High
	case probe.OutcomeCrash, probe.OutcomeTimeout:
		return findings.High
	case probe.OutcomeInternalError:
		return findings.Medium
	default: // OutcomeToolError, OutcomeSkippedUnsafe (not reportable; listed for exhaustiveness)
		return findings.Info
	}
}
