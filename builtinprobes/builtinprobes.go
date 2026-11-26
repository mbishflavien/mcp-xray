// Package builtinprobes constructs mcp-xray's own probes as public
// probe.Probe values. It is the one bridge between the public API and
// internal/probes: an out-of-tree package composes these alongside its
// own probes without ever importing internal/probes directly, which Go's
// internal/ import rule would forbid anyway.
package builtinprobes

import (
	"github.com/mbishflavien/mcp-xray/internal/probes"
	"github.com/mbishflavien/mcp-xray/probe"
)

// SchemaFuzz returns the schema-fuzz probe: it generates adversarial
// mutations from each tool's input schema (sandboxed as a WASI module)
// and calls the tool with each one.
func SchemaFuzz() probe.ToolProbe {
	return probes.NewSchemaFuzz()
}

// AuthBypass returns the auth-bypass probe: for each tool whose input
// schema has a field shaped like an identity, a privilege, or a credential,
// it calls the tool with a forged value for that field (sandboxed as a WASI
// module to generate it) and flags the ones that get silently accepted.
func AuthBypass() probe.ToolProbe {
	return probes.NewAuthBypass()
}

// RateLimit returns the rate-limit probe: for every tool, it calls that
// tool with the same benign arguments several times in a row and flags a
// tool that crashes or hangs under that repeated load (High), or one that
// shows no sign of being rate-limited at all (Low).
func RateLimit() probe.ServerProbe {
	return probes.NewRateLimit()
}
