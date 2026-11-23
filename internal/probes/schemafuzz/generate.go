// Package schemafuzz generates adversarial payloads from a tool's JSON
// Schema. The logic lives here as plain, natively-testable Go; cmd/probes/schemafuzz
// wraps it as a stdin/stdout program so it can also run sandboxed as WASI.
package schemafuzz

import (
	"encoding/json"
	"fmt"
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

// Generate returns the mutations to try for the given tool and schema, or
// an error message (not a Go error, since this crosses the WASI boundary as
// plain JSON) if the schema can't be parsed.
func Generate(toolName string, schema json.RawMessage) ([]probeproto.Mutation, string) {
	var s objectSchema
	if err := json.Unmarshal(schema, &s); err != nil {
		return nil, fmt.Sprintf("parse schema: %v", err)
	}

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
			args := cloneArgs(base)
			args[name] = strings.Repeat("A", oversizedStringLen)
			mutations = append(mutations, probeproto.Mutation{
				ID:          fmt.Sprintf("%s/oversized-string/%s", toolName, name),
				Kind:        "oversized_string",
				Description: fmt.Sprintf("send a %d-character string for %q", oversizedStringLen, name),
				Args:        args,
			})

			args = cloneArgs(base)
			args[name] = "../../../../../../etc/passwd"
			mutations = append(mutations, probeproto.Mutation{
				ID:          fmt.Sprintf("%s/path-traversal/%s", toolName, name),
				Kind:        "path_traversal",
				Description: fmt.Sprintf("send a path-traversal string for %q", name),
				Args:        args,
			})
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
	for k, v := range src {
		dst[k] = v
	}
	return dst
}
