package probes

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/mbishflavien/mcp-xray/findings"
	"github.com/mbishflavien/mcp-xray/probe"
)

// defaultBurstSize is how many times RateLimit calls a tool with the same
// benign arguments before concluding nothing load-related happened. Small
// and fixed, matching schema-fuzz/auth-bypass's own precedent of bounding
// *per-tool* resource use (there, maxSchemaFields; here, the burst) rather
// than how many tools get probed.
const defaultBurstSize = 5

// Kind values this probe reports. All four are reportable; which fires
// depends on how a burst of identical calls against one tool behaves.
const (
	// KindDoS fires when a later call in the burst crashes or hangs the
	// tool: repeated, valid-looking calls broke something a single one
	// didn't - a resource-exhaustion denial-of-service risk.
	KindDoS = "rate_limit_dos"
	// KindInternalError fires when a later call triggers a JSON-RPC
	// internal error under load.
	KindInternalError = "rate_limit_internal_error"
	// KindSkipped fires when the safety policy blocked the tool before any
	// burst call was made, mirroring how schema-fuzz/auth-bypass surface
	// the same thing.
	KindSkipped = "rate_limit_skipped_unsafe"
)

// RateLimit is a probe.ServerProbe: for every tool the server advertises,
// it calls that tool with the same benign, valid-looking arguments several
// times in a row ("a burst") and checks whether the server treats repeated
// calls any differently from a single one. It is a ServerProbe, not a
// ToolProbe, because that's exactly what probe.ServerContext's own doc
// comment names as the reason ServerProbe exists.
type RateLimit struct {
	// CallTimeout bounds each individual call. A call that doesn't return
	// within this window is treated as a hang (probe.OutcomeTimeout).
	CallTimeout time.Duration
	// BurstSize is how many identical calls to make per tool.
	BurstSize int
}

// NewRateLimit returns a RateLimit probe with sensible defaults.
func NewRateLimit() *RateLimit {
	return &RateLimit{CallTimeout: defaultCallTimeout, BurstSize: defaultBurstSize}
}

// ID implements probe.Probe.
func (p *RateLimit) ID() string { return "rate-limit" }

// RunServer implements probe.ServerProbe.
func (p *RateLimit) RunServer(ctx context.Context, sc probe.ServerContext) ([]findings.Finding, error) {
	timeout := p.CallTimeout
	if timeout <= 0 {
		timeout = defaultCallTimeout
	}
	burst := p.BurstSize
	if burst <= 0 {
		burst = defaultBurstSize
	}

	var out []findings.Finding
	var errs []error
	for _, tool := range sc.Snapshot.Tools {
		schema, err := json.Marshal(tool.InputSchema)
		if err != nil {
			errs = append(errs, fmt.Errorf("marshal input schema for %q: %w", tool.Name, err))
			continue
		}
		args, err := RateLimitBaseline(ctx, tool.Name, schema)
		if err != nil {
			errs = append(errs, fmt.Errorf("generate rate-limit baseline for %q: %w", tool.Name, err))
			continue
		}
		out = append(out, p.burstTool(ctx, sc.Caller, tool.Name, args, burst, timeout)...)
	}
	return out, errors.Join(errs...)
}

// burstTool calls toolName with args, unchanged, up to burst times, turning
// a load-attributable failure into a Finding. It never attributes the
// *first* call's outcome to the burst: a tool that's already broken (or
// already rejects, or is already blocked) on a single valid-looking call
// isn't a rate-limiting finding - schema-fuzz and auth-bypass already cover
// "this tool is broken" or "this tool is blocked" on their own terms. The
// one exception is OutcomeSkippedUnsafe, which is unambiguous regardless of
// position and is worth noting once, matching how schema-fuzz/auth-bypass
// already surface a blocked tool.
func (p *RateLimit) burstTool(ctx context.Context, caller probe.ToolCaller, toolName string, args map[string]any, burst int, timeout time.Duration) []findings.Finding {
	var out []findings.Finding
	reportedInternalError := false

	for i := range burst {
		callCtx, cancel := context.WithTimeout(ctx, timeout)
		result, callErr := caller.CallTool(callCtx, toolName, args)
		cancel()

		outcome := probe.Classify(result, callErr)
		switch outcome {
		case probe.OutcomeSkippedUnsafe:
			return append(out, findings.Finding{
				ProbeID:  p.ID(),
				Severity: findings.Info,
				Kind:     KindSkipped,
				Title:    fmt.Sprintf("%s: %s", KindSkipped, outcome),
				Detail:   "the safety policy blocked this tool before any burst call was made",
				Target:   toolName,
				Evidence: evidenceFor(result, callErr),
			})
		case probe.OutcomeCrash, probe.OutcomeTimeout:
			if i == 0 {
				return out
			}
			return append(out, findings.Finding{
				ProbeID:  p.ID(),
				Severity: findings.High,
				Kind:     KindDoS,
				Title:    fmt.Sprintf("%s: %s", KindDoS, outcome),
				Detail:   fmt.Sprintf("a burst of identical, valid-looking calls crashed or hung the tool on call %d of %d", i+1, burst),
				Target:   toolName,
				Evidence: evidenceFor(result, callErr),
			})
		case probe.OutcomeInternalError:
			if i == 0 {
				return out
			}
			if !reportedInternalError {
				out = append(out, findings.Finding{
					ProbeID:  p.ID(),
					Severity: findings.Medium,
					Kind:     KindInternalError,
					Title:    fmt.Sprintf("%s: %s", KindInternalError, outcome),
					Detail:   fmt.Sprintf("a burst of identical calls triggered an internal error on call %d of %d", i+1, burst),
					Target:   toolName,
					Evidence: evidenceFor(result, callErr),
				})
				reportedInternalError = true
			}
			continue
		case probe.OutcomeToolError:
			// Either the baseline args aren't valid for this tool (if this
			// is the first call - the same unresolved-schema caveat
			// schema-fuzz/auth-bypass document) or a later rejection is
			// itself a throttling signal: healthy. Either way, nothing to
			// report.
			return out
		}
	}
	return out
}
