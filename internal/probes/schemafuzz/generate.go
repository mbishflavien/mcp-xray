// Package schemafuzz generates adversarial payloads from a tool's JSON
// Schema. The logic lives here as plain, natively-testable Go; cmd/probes/schemafuzz
// wraps it as a stdin/stdout program so it can also run sandboxed as WASI.
package schemafuzz

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/mbishflavien/mcp-xray/internal/probeproto"
	"github.com/mbishflavien/mcp-xray/internal/probes/schemashape"
)

const oversizedStringLen = 100_000

// Generate returns the mutations to try for the given tool and schema, or
// an error message (not a Go error, since this crosses the WASI boundary as
// plain JSON) if the schema can't be parsed.
func Generate(toolName string, schema json.RawMessage) ([]probeproto.Mutation, string) {
	var s schemashape.ObjectSchema
	if err := json.Unmarshal(schema, &s); err != nil {
		return nil, fmt.Sprintf("parse schema: %v", err)
	}
	s = schemashape.Cap(s)

	base := schemashape.BaseArgs(s)
	var mutations []probeproto.Mutation

	for _, name := range s.Required {
		args := schemashape.CloneArgs(base)
		delete(args, name)
		mutations = append(mutations, probeproto.Mutation{
			ID:          fmt.Sprintf("%s/missing-required/%s", toolName, name),
			Kind:        "missing_required",
			Description: fmt.Sprintf("omit required field %q", name),
			Args:        args,
		})
	}

	for name, prop := range s.Properties {
		switch prop.Type {
		case "string":
			mutations = append(mutations, stringMutations(toolName, name, base)...)
		case "number", "integer":
			args := schemashape.CloneArgs(base)
			args[name] = "not-a-number"
			mutations = append(mutations, probeproto.Mutation{
				ID:          fmt.Sprintf("%s/type-confusion/%s", toolName, name),
				Kind:        "type_confusion",
				Description: fmt.Sprintf("send a string where %q expects a number", name),
				Args:        args,
			})
		}
	}

	if len(base) > 0 || len(s.Properties) > 0 {
		args := schemashape.CloneArgs(base)
		args["__mcp_xray_unexpected_field__"] = true
		mutations = append(mutations, probeproto.Mutation{
			ID:          fmt.Sprintf("%s/mass-assignment", toolName),
			Kind:        "mass_assignment",
			Description: "send an extra field the schema never declared",
			Args:        args,
		})
	}

	return mutations, ""
}

// stringMutation is one (kind, value, description) triple to try for a
// string-typed property.
type stringMutation struct {
	kind, value, description string
}

var stringMutationTable = []stringMutation{
	{"oversized_string", strings.Repeat("A", oversizedStringLen), fmt.Sprintf("send a %d-character string", oversizedStringLen)},
	{"path_traversal", "../../../../../../etc/passwd", "send a path-traversal string"},
	{"null_byte_injection", "mcp-xray-probe\x00", "send a string with an embedded null byte"},
	{"sql_injection", "' OR '1'='1'; DROP TABLE users; --", "send a SQL-injection string"},
	{"shell_injection", "; rm -rf / #", "send a shell-injection string"},
	{"template_injection", "{{7*7}}${7*7}<%= 7*7 %>", "send a template-injection string"},
}

// stringMutations returns one mutation per entry in stringMutationTable for
// the given property, each varying only that property.
func stringMutations(toolName, name string, base map[string]any) []probeproto.Mutation {
	out := make([]probeproto.Mutation, 0, len(stringMutationTable))
	for _, sm := range stringMutationTable {
		args := schemashape.CloneArgs(base)
		args[name] = sm.value
		out = append(out, probeproto.Mutation{
			ID:          fmt.Sprintf("%s/%s/%s", toolName, strings.ReplaceAll(sm.kind, "_", "-"), name),
			Kind:        sm.kind,
			Description: fmt.Sprintf("%s for %q", sm.description, name),
			Args:        args,
		})
	}
	return out
}
