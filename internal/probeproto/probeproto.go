// Package probeproto defines the JSON wire types exchanged between the Go
// host and sandboxed WASI probes over stdin/stdout. Both sides import this
// package, so the "ABI" is ordinary typed Go code rather than a hand-rolled
// binary format.
package probeproto

import "encoding/json"

// MutationRequest is what the host sends a mutation-generating probe (for
// example schema-fuzz or auth-bypass) on stdin: the one tool's name and its
// input schema.
type MutationRequest struct {
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

// MutationResponse is what a mutation-generating probe writes to stdout.
type MutationResponse struct {
	Mutations []Mutation `json:"mutations"`
	Error     string     `json:"error,omitempty"`
}
