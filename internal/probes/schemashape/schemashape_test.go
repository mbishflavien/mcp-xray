package schemashape

import (
	"fmt"
	"testing"
)

func TestBaseArgsFillsEveryKnownType(t *testing.T) {
	args := BaseArgs(ObjectSchema{Properties: map[string]PropertySpec{
		"name":   {Type: "string"},
		"age":    {Type: "number"},
		"count":  {Type: "integer"},
		"active": {Type: "boolean"},
		"nested": {Type: "object"}, // unhandled type: skipped, not guessed at
	}})

	want := map[string]any{"name": "mcp-xray-probe", "age": 1, "count": 1, "active": true}
	if len(args) != len(want) {
		t.Fatalf("BaseArgs() = %v, want exactly %v", args, want)
	}
	for k, v := range want {
		if args[k] != v {
			t.Errorf("BaseArgs()[%q] = %v, want %v", k, args[k], v)
		}
	}
}

func TestCloneArgsIsIndependent(t *testing.T) {
	src := map[string]any{"name": "original"}
	clone := CloneArgs(src)
	clone["name"] = "changed"

	if src["name"] != "original" {
		t.Errorf("CloneArgs() mutation leaked back into src: %v", src)
	}
}

// TestCapTrimsAnAdversarialSchema confirms a schema with far more required
// entries and properties than any reasonable tool would declare gets capped
// at MaxFields of each, rather than letting a malicious or buggy MCP server
// inflate a probe's resource use via its advertised schema.
func TestCapTrimsAnAdversarialSchema(t *testing.T) {
	const propertyCount = 10_000

	properties := make(map[string]PropertySpec, propertyCount)
	required := make([]string, 0, propertyCount)
	for i := range propertyCount {
		name := fmt.Sprintf("field_%d", i)
		properties[name] = PropertySpec{Type: "string"}
		required = append(required, name)
	}

	capped := Cap(ObjectSchema{Properties: properties, Required: required})

	if len(capped.Properties) != MaxFields {
		t.Errorf("Cap() left %d properties, want exactly %d", len(capped.Properties), MaxFields)
	}
	if len(capped.Required) != MaxFields {
		t.Errorf("Cap() left %d required entries, want exactly %d", len(capped.Required), MaxFields)
	}
}

func TestCapLeavesASmallSchemaUntouched(t *testing.T) {
	s := ObjectSchema{
		Properties: map[string]PropertySpec{"name": {Type: "string"}},
		Required:   []string{"name"},
	}
	capped := Cap(s)
	if len(capped.Properties) != 1 || len(capped.Required) != 1 {
		t.Errorf("Cap() changed a schema well under MaxFields: %+v", capped)
	}
}
