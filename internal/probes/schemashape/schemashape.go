// Package schemashape parses the flat-object subset of JSON Schema that
// mcp-xray's probes understand, and builds the placeholder argument sets
// they fill a tool's other fields with. schema-fuzz, auth-bypass, and
// rate-limit each need this exact logic; it lives here once instead of
// three times, so a fix (or a future improvement, like real $ref
// resolution) only has to happen in one place.
package schemashape

import "maps"

// ObjectSchema covers the subset of JSON Schema every probe understands: a
// flat object with typed properties and a required list. Nested schemas,
// $ref, oneOf/anyOf, and array item schemas are not resolved; properties
// using them are skipped rather than guessed at.
type ObjectSchema struct {
	Type       string                  `json:"type"`
	Properties map[string]PropertySpec `json:"properties"`
	Required   []string                `json:"required"`
}

// PropertySpec is the one piece of a property's schema every probe here
// cares about: its declared JSON type.
type PropertySpec struct {
	Type string `json:"type"`
}

// MaxFields caps how many required entries and how many properties a probe
// will consider. A malicious or buggy MCP server could otherwise advertise
// a tool with an enormous schema to inflate the scanner's own memory and
// the number of real calls a scan makes. 200 is far more than any
// reasonable tool declares.
const MaxFields = 200

// Cap trims s down to MaxFields required entries and MaxFields properties,
// so every downstream step (BaseArgs, a probe's own mutation loop) naturally
// respects the cap without each needing its own counter. Map iteration
// order is unspecified, so which fields survive is arbitrary - that's fine,
// this is a bound on scanner resource use, not a guarantee of which fields
// get tested.
func Cap(s ObjectSchema) ObjectSchema {
	if len(s.Required) > MaxFields {
		s.Required = s.Required[:MaxFields]
	}
	if len(s.Properties) > MaxFields {
		trimmed := make(map[string]PropertySpec, MaxFields)
		for name, prop := range s.Properties {
			if len(trimmed) >= MaxFields {
				break
			}
			trimmed[name] = prop
		}
		s.Properties = trimmed
	}
	return s
}

// BaseArgs builds a minimal valid-looking argument set so a probe's own
// mutation only varies the field(s) it's actually testing.
func BaseArgs(s ObjectSchema) map[string]any {
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

// CloneArgs returns an independent copy of src, so mutating the copy never
// affects the shared base args a probe generated it from.
func CloneArgs(src map[string]any) map[string]any {
	dst := make(map[string]any, len(src))
	maps.Copy(dst, src)
	return dst
}
