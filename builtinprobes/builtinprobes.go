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
