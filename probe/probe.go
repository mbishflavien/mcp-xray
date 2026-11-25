// Package probe defines the public interfaces every security probe
// implements and the context a probe runs with. It is deliberately outside
// internal/ so a future out-of-tree package (for example a private
// enterprise module built on top of mcp-xray) can implement and register
// its own probes without needing access to anything under internal/.
package probe

import (
	"context"
	"time"

	"github.com/mbishflavien/mcp-xray/findings"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ToolCaller calls one tool on a connected MCP server. *inspector.Session
// satisfies this structurally; probes and the runner never import
// internal/inspector directly, so inspector is free to grow (for example,
// an HTTP transport) without touching this public surface.
type ToolCaller interface {
	CallTool(ctx context.Context, name string, args map[string]any) (*mcp.CallToolResult, error)
}

// Snapshot is everything a target server advertised at connect time. It
// mirrors inspector.CapabilitySnapshot but is decoupled from it so probe
// does not need to import internal/inspector.
type Snapshot struct {
	ServerName    string
	ServerVersion string
	Tools         []*mcp.Tool
	Resources     []*mcp.Resource
	Prompts       []*mcp.Prompt
}

// ToolContext is what a ToolProbe runs with: a safety-gated caller, the one
// tool it's probing, the full server snapshot for cross-referencing, and
// the per-call timeout to apply.
type ToolContext struct {
	Caller      ToolCaller
	Tool        *mcp.Tool
	Snapshot    Snapshot
	CallTimeout time.Duration
}

// ServerContext is what a ServerProbe runs with: the same gated caller and
// snapshot, but no single target tool, for checks that span the server as
// a whole (for example rate-limit probing).
type ServerContext struct {
	Caller      ToolCaller
	Snapshot    Snapshot
	CallTimeout time.Duration
}

// Probe is the identity every probe shares.
type Probe interface {
	// ID names the probe, used as Finding.ProbeID and in reports.
	ID() string
}

// ToolProbe runs once per tool the target server advertises.
type ToolProbe interface {
	Probe
	RunTool(ctx context.Context, tc ToolContext) ([]findings.Finding, error)
}

// ServerProbe runs once for the whole server rather than once per tool.
type ServerProbe interface {
	Probe
	RunServer(ctx context.Context, sc ServerContext) ([]findings.Finding, error)
}
