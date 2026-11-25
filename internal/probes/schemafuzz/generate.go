// Package schemafuzz generates adversarial payloads from a tool's JSON
// Schema. The logic lives here as plain, natively-testable Go; cmd/probes/schemafuzz
// wraps it as a stdin/stdout program so it can also run sandboxed as WASI.
package schemafuzz

import (
	"encoding/json"
	"fmt"
	"maps"
	"strings"

	"github.com/mbishflavien/mcp-xray/internal/probeproto"
)

// objectSchema covers the subset of JSON Schema this probe understands:
// a flat object with typed properties and a required list. Nested schemas,
// $ref, oneOf/anyOf, and array item schemas are not resolved; properties
// using them are skipped rather than guessed at.
type objectSchema struct {
	Type       string                  `json:"type"`
	Properties map[string]propertySpec `json:"properties"`
	Required   []string                `json:"required"`
}

type propertySpec struct {
	Type string `json:"type"`
}

const oversizedStringLen = 100_000

// maxSchemaFields caps how many required entries and how many properties
// Generate will fuzz. A malicious or buggy MCP server could otherwise
// advertise a tool with an enormous schema - each property can drive
// several mutations, one of them a 100KB string - to blow up the
// scanner's own memory and the time a scan takes (thousands of real
// CallTool invocations against the target). 200 is already far more than
// any reasonable tool declares.
const maxSchemaFields = 200

// Generate returns the mutations to try for the given tool and schema, or
// an error message (not a Go error, since this crosses the WASI boundary as
// plain JSON) if the schema can't be parsed.
func Generate(toolName string, schema json.RawMessage) ([]probeproto.Mutation, string) {
	var s objectSchema
	if err := json.Unmarshal(schema, &s); err != nil {
		return nil, fmt.Sprintf("parse schema: %v", err)
	}
	s = capSchema(s)

	base := baseArgs(s)
	var mutations []probeproto.Mutation

	for _, name := range s.Required {
		args := cloneArgs(base)
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
			args := cloneArgs(base)
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
		args := cloneArgs(base)
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
		args := cloneArgs(base)
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

// capSchema trims an oversized schema down to maxSchemaFields required
// entries and maxSchemaFields properties, so every downstream step
// (baseArgs, the mutation loops, the mass-assignment check) naturally
// respects the cap without each needing its own counter. Map iteration
// order is unspecified, so which fields survive is arbitrary, not
// necessarily the "first" ones - that's fine, this is a bound on scanner
// resource use, not a guarantee of which fields get tested.
func capSchema(s objectSchema) objectSchema {
	if len(s.Required) > maxSchemaFields {
		s.Required = s.Required[:maxSchemaFields]
	}
	if len(s.Properties) > maxSchemaFields {
		trimmed := make(map[string]propertySpec, maxSchemaFields)
		for name, prop := range s.Properties {
			if len(trimmed) >= maxSchemaFields {
				break
			}
			trimmed[name] = prop
		}
		s.Properties = trimmed
	}
	return s
}

// baseArgs builds a minimal valid-looking argument set so each mutation only
// varies the one field it's testing.
func baseArgs(s objectSchema) map[string]any {
	args := make(map[string]any, len(s.Properties))
	for name, prop := range s.Properties {
		switch prop.Type {
		case "string":
			args[name] = "mcp-xray-probe"
		case "number", "integer":
			args[name] = 1
		case "boolean":
			args[name] = true
		}
	}
	return args
}

func cloneArgs(src map[string]any) map[string]any {
	dst := make(map[string]any, len(src))
	maps.Copy(dst, src)
	return dst
}
