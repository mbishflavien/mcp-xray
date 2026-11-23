// Package probeproto defines the JSON wire types exchanged between the Go
// host and sandboxed WASI probes over stdin/stdout. Both sides import this
// package, so the "ABI" is ordinary typed Go code rather than a hand-rolled
// binary format.
package probeproto

import "encoding/json"

// SchemaFuzzInput is what the host sends a schema-fuzz probe on stdin.
type SchemaFuzzInput struct {
	ToolName string          `json:"toolName"`
	Schema   json.RawMessage `json:"schema"`
}

// Mutation is one adversarial payload a probe wants the host to try against
// the real tool. If the call succeeds (or fails in the wrong way) when it
// shouldn't, that is evidence for a Finding.
type Mutation struct {
	ID          string         `json:"id"`
	Kind        string         `json:"kind"`
	Description string         `json:"description"`
	Args        map[string]any `json:"args"`
}

// SchemaFuzzOutput is what a schema-fuzz probe writes to stdout.
type SchemaFuzzOutput struct {
	Mutations []Mutation `json:"mutations"`
	Error     string     `json:"error,omitempty"`
}
