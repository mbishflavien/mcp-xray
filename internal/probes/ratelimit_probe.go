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

// defaultMaxDuration bounds the whole probe's wall-clock time across every
// tool, not just one tool's burst. BurstSize x toolCount x CallTimeout can
// stack up on a server with many slow or hanging tools - this is the one
// resource-use risk rate-limit introduces that schema-fuzz/auth-bypass
// don't have, since neither of them multiplies calls by a burst factor.
const defaultMaxDuration = 2 * time.Minute

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
	// KindAbsent fires when an entire burst succeeds with no rejection and
	// no meaningful growth in latency: nothing suggests this tool is
	// rate-limited at all. A missing-control finding, not a bug.
	KindAbsent = "rate_limit_absent"
)

// Thresholds for the latency-growth heuristic noThrottleSignal uses when a
// burst never gets rejected outright. Deliberately crude and documented as
// such: a server whose real rate limit only kicks in past burst calls, or
// one that just happens to slow down for an unrelated reason (a GC pause,
// disk I/O), can fool this in either direction. It exists to catch a
// softer signal than an outright rejection - a server quietly throttling by
// delaying responses - without pretending to be a real statistical test.
const (
	// minLatencySamples is the fewest successful calls needed before the
	// heuristic says anything at all; below this, there's too little data
	// to call a difference meaningful one way or the other.
	minLatencySamples = 4
	// latencyGrowthFactor is how much slower the burst's second half has
	// to be, on average, than its first half.
	latencyGrowthFactor = 2.0
	// minLatencyGrowthAbs is the minimum absolute growth required on top
	// of latencyGrowthFactor, so two calls that both took near-zero time
	// (say, 1ms and 3ms) don't count as "3x slower".
	minLatencyGrowthAbs = 50 * time.Millisecond
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
	// MaxDuration bounds how long RunServer spends on the whole server,
	// across every tool. Once exceeded, no *new* tool's burst is started -
	// a burst already in progress still finishes - and RunServer returns
	// whatever it found so far instead of working through every tool.
	MaxDuration time.Duration
}

// NewRateLimit returns a RateLimit probe with sensible defaults.
func NewRateLimit() *RateLimit {
	return &RateLimit{CallTimeout: defaultCallTimeout, BurstSize: defaultBurstSize, MaxDuration: defaultMaxDuration}
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
	maxDuration := p.MaxDuration
	if maxDuration <= 0 {
		maxDuration = defaultMaxDuration
	}

	start := time.Now()
	var out []findings.Finding
	var errs []error
	for _, tool := range sc.Snapshot.Tools {
		if time.Since(start) > maxDuration {
			break
		}
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
	var durations []time.Duration
	reportedInternalError := false

	for i := range burst {
		callCtx, cancel := context.WithTimeout(ctx, timeout)
		start := time.Now()
		result, callErr := caller.CallTool(callCtx, toolName, args)
		elapsed := time.Since(start)
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
		durations = append(durations, elapsed)
	}

	if len(out) == 0 && noThrottleSignal(durations) {
		out = append(out, findings.Finding{
			ProbeID:  p.ID(),
			Severity: findings.Low,
			Kind:     KindAbsent,
			Title:    fmt.Sprintf("%s: no rate limiting observed", KindAbsent),
			Detail:   fmt.Sprintf("%d identical calls all succeeded with no sign of throttling: no rejection, and no meaningful growth in latency", len(durations)),
			Target:   toolName,
			Evidence: summarizeDurations(durations),
		})
	}
	return out
}

// noThrottleSignal reports whether a completed, all-successful burst showed
// no sign the server treats repeated calls any differently from a single
// one. See the threshold constants above for its documented limitations.
func noThrottleSignal(d []time.Duration) bool {
	if len(d) < minLatencySamples {
		return true
	}
	mid := len(d) / 2
	firstAvg := averageDuration(d[:mid])
	secondAvg := averageDuration(d[mid:])
	grew := secondAvg >= time.Duration(float64(firstAvg)*latencyGrowthFactor) && secondAvg-firstAvg >= minLatencyGrowthAbs
	return !grew
}

func averageDuration(d []time.Duration) time.Duration {
	var total time.Duration
	for _, v := range d {
		total += v
	}
	return total / time.Duration(len(d))
}

// summarizeDurations gives the Absent finding's Evidence something
// concrete to show instead of leaving it empty, since there's no error
// text to report.
func summarizeDurations(d []time.Duration) string {
	if len(d) == 0 {
		return ""
	}
	return fmt.Sprintf("%d calls succeeded; first took %v, last took %v", len(d), d[0], d[len(d)-1])
}
