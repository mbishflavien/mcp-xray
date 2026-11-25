package schemafuzz

import (
	"encoding/json"
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
