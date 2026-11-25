// Package scan is mcp-xray's composition root: it runs a set of probes
// against a connected server's snapshot, gating every tool call through a
// SafetyPolicy so no probe can call a destructive-looking tool without an
// explicit opt-in. It is public so a binary built on top of mcp-xray (for
// example a future enterprise CLI) can reuse the same runner with its own
// probes, without forking anything under internal/.
package scan

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/mbishflavien/mcp-xray/findings"
	"github.com/mbishflavien/mcp-xray/probe"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Options configures a Runner.
type Options struct {
	// CallTimeout is the default per-call timeout handed to every probe
	// via ToolContext/ServerContext. Probes may still impose their own,
	// tighter timeout.
	CallTimeout time.Duration
	// Policy gates every tool call. A nil Policy allows every call.
	Policy probe.SafetyPolicy
}

// Runner runs a fixed set of probes against a target server.
type Runner struct {
	probes []probe.Probe
	opts   Options
}

// NewRunner returns a Runner that will run every given probe.
func NewRunner(probes []probe.Probe, opts Options) *Runner {
	return &Runner{probes: probes, opts: opts}
}

// Run calls every ToolProbe once per tool in snap and every ServerProbe
// once, aggregating their Findings. A probe returning an error does not
// abort the run: its error is joined into the returned error and every
// other probe still runs.
func (r *Runner) Run(ctx context.Context, caller probe.ToolCaller, snap probe.Snapshot) ([]findings.Finding, error) {
	gated := &gatedCaller{real: caller, policy: r.opts.Policy, snap: snap}

	var all []findings.Finding
	var errs []error

	for _, p := range r.probes {
		if tp, ok := p.(probe.ToolProbe); ok {
			for _, tool := range snap.Tools {
				tc := probe.ToolContext{
					Caller:      gated,
					Tool:        tool,
					Snapshot:    snap,
					CallTimeout: r.opts.CallTimeout,
				}
				found, err := tp.RunTool(ctx, tc)
				all = append(all, found...)
				if err != nil {
					errs = append(errs, fmt.Errorf("%s/%s: %w", p.ID(), tool.Name, err))
				}
			}
		}
		if sp, ok := p.(probe.ServerProbe); ok {
			sc := probe.ServerContext{
				Caller:      gated,
				Snapshot:    snap,
				CallTimeout: r.opts.CallTimeout,
			}
			found, err := sp.RunServer(ctx, sc)
			all = append(all, found...)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", p.ID(), err))
			}
		}
	}

	return all, errors.Join(errs...)
}

// gatedCaller wraps a real probe.ToolCaller so every call is checked
// against a SafetyPolicy first. This is the single enforcement point:
// every probe gets it for free through ToolContext.Caller/ServerContext.Caller
// without needing to know a SafetyPolicy exists.
type gatedCaller struct {
	real   probe.ToolCaller
	policy probe.SafetyPolicy
	snap   probe.Snapshot
}

func (g *gatedCaller) CallTool(ctx context.Context, name string, args map[string]any) (*mcp.CallToolResult, error) {
	if g.policy != nil {
		tool := g.findTool(name)
		if tool != nil {
			if ok, reason := g.policy.Allow(tool); !ok {
				return nil, &probe.BlockedError{Tool: name, Reason: reason}
			}
		}
	}
	return g.real.CallTool(ctx, name, args)
}

func (g *gatedCaller) findTool(name string) *mcp.Tool {
	for _, t := range g.snap.Tools {
		if t.Name == name {
			return t
		}
	}
	return nil
}
