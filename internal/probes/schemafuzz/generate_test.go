package schemafuzz

import (
	"encoding/json"
	"fmt"
	"testing"
)

func kindCounts(t *testing.T, toolName string, schema string) map[string]int {
	t.Helper()
	mutations, errMsg := Generate(toolName, json.RawMessage(schema))
	if errMsg != "" {
		t.Fatalf("Generate() error: %s", errMsg)
	}
	counts := make(map[string]int)
	for _, m := range mutations {
		counts[m.Kind]++
	}
	return counts
}

// TestGenerateCapsAnAdversarialSchema confirms a schema with far more
// properties than any reasonable tool would declare doesn't blow up
// Generate's output. A malicious or buggy MCP server could otherwise use
// this to exhaust the scanner's own memory and the time a scan takes.
func TestGenerateCapsAnAdversarialSchema(t *testing.T) {
	const propertyCount = 10_000

	properties := make(map[string]map[string]string, propertyCount)
	required := make([]string, 0, propertyCount)
	for i := range propertyCount {
		name := fmt.Sprintf("field_%d", i)
		properties[name] = map[string]string{"type": "string"}
		required = append(required, name)
	}
	schema, err := json.Marshal(map[string]any{
		"type":       "object",
		"properties": properties,
		"required":   required,
	})
	if err != nil {
		t.Fatalf("marshal adversarial schema: %v", err)
	}

	mutations, errMsg := Generate("greet", schema)
	if errMsg != "" {
		t.Fatalf("Generate() error: %s", errMsg)
	}

	// Each capped field can drive at most len(stringMutationTable)
	// mutations, plus one missing_required entry, plus one
	// mass-assignment mutation overall - nowhere near
	// propertyCount * (len(stringMutationTable) + 1).
	maxExpected := maxSchemaFields*(len(stringMutationTable)+1) + 1
	if len(mutations) > maxExpected {
		t.Errorf("Generate() produced %d mutations from %d properties, want at most %d",
			len(mutations), propertyCount, maxExpected)
	}
	if len(mutations) == 0 {
		t.Error("Generate() produced no mutations at all, want some (just capped)")
	}
}

func TestGenerateMissingRequired(t *testing.T) {
	counts := kindCounts(t, "greet", `{
		"type": "object",
		"properties": {"name": {"type": "string"}, "age": {"type": "number"}},
		"required": ["name"]
	}`)
	if counts["missing_required"] != 1 {
		t.Errorf("missing_required count = %d, want 1", counts["missing_required"])
	}
}

func TestGenerateStringMutations(t *testing.T) {
	counts := kindCounts(t, "greet", `{
		"type": "object",
		"properties": {"name": {"type": "string"}}
	}`)
	if counts["oversized_string"] != 1 {
		t.Errorf("oversized_string count = %d, want 1", counts["oversized_string"])
	}
	if counts["path_traversal"] != 1 {
		t.Errorf("path_traversal count = %d, want 1", counts["path_traversal"])
	}
	for _, kind := range []string{
		"null_byte_injection", "sql_injection", "shell_injection", "template_injection",
	} {
		if counts[kind] != 1 {
			t.Errorf("%s count = %d, want 1", kind, counts[kind])
		}
	}
}

func TestGenerateNumberMutation(t *testing.T) {
	counts := kindCounts(t, "greet", `{
		"type": "object",
		"properties": {"age": {"type": "number"}}
	}`)
	if counts["type_confusion"] != 1 {
		t.Errorf("type_confusion count = %d, want 1", counts["type_confusion"])
	}
}

func TestGenerateMassAssignment(t *testing.T) {
	counts := kindCounts(t, "greet", `{
		"type": "object",
		"properties": {"name": {"type": "string"}}
	}`)
	if counts["mass_assignment"] != 1 {
		t.Errorf("mass_assignment count = %d, want 1", counts["mass_assignment"])
	}
}

func TestGenerateInvalidSchema(t *testing.T) {
	_, errMsg := Generate("greet", json.RawMessage(`not json`))
	if errMsg == "" {
		t.Error("Generate() with invalid schema should return an error message")
	}
}
