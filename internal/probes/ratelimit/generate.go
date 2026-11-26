// Package ratelimit generates the benign, repeatable argument set the
// rate-limit probe bursts a tool with. The logic lives here as plain,
// natively-testable Go; cmd/probes/ratelimit wraps it as a stdin/stdout
// program so it can also run sandboxed as WASI - the same arrangement
// internal/probes/schemafuzz and internal/probes/authbypass use.
package ratelimit

import (
	"encoding/json"
	"fmt"

	"github.com/mbishflavien/mcp-xray/internal/probeproto"
	"github.com/mbishflavien/mcp-xray/internal/probes/schemashape"
)

// Generate returns exactly one mutation: a minimal, valid-looking argument
// set to repeat unchanged for every call in a burst, or an error message
// (not a Go error, since this crosses the WASI boundary as plain JSON) if
// the schema can't be parsed.
//
// Unlike schema-fuzz and auth-bypass, this isn't trying to craft an
// adversarial payload - it needs a *benign* one, so the host can tell
// whether the server treats repeated, valid calls any differently from a
// single one. A tool with no properties at all still gets a (empty)
// baseline, since calling it with no arguments repeatedly is still a valid
// thing to burst-test.
func Generate(toolName string, schema json.RawMessage) ([]probeproto.Mutation, string) {
	var s schemashape.ObjectSchema
	if err := json.Unmarshal(schema, &s); err != nil {
		return nil, fmt.Sprintf("parse schema: %v", err)
	}
	s = schemashape.Cap(s)

	return []probeproto.Mutation{{
		ID:          fmt.Sprintf("%s/rate-limit/baseline", toolName),
		Kind:        "rate_limit_baseline",
		Description: "a minimal, valid-looking argument set, repeated unchanged for every call in the burst",
		Args:        schemashape.BaseArgs(s),
	}}, ""
}
