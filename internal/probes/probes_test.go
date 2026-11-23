package probes

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func TestSchemaFuzzMutationsEndToEnd(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	schema := json.RawMessage(`{
		"type": "object",
		"properties": {"name": {"type": "string"}},
		"required": ["name"]
	}`)

	mutations, err := SchemaFuzzMutations(ctx, "greet", schema)
	if err != nil {
		t.Fatalf("SchemaFuzzMutations() error: %v", err)
	}

	kinds := make(map[string]bool)
	for _, m := range mutations {
		kinds[m.Kind] = true
	}
	for _, want := range []string{"missing_required", "oversized_string", "path_traversal", "mass_assignment"} {
		if !kinds[want] {
			t.Errorf("mutations missing kind %q; got %v", want, mutations)
		}
	}
}

func TestSchemaFuzzMutationsInvalidSchema(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := SchemaFuzzMutations(ctx, "greet", json.RawMessage(`not json`))
	if err == nil {
		t.Error("SchemaFuzzMutations() with invalid schema should return an error")
	}
}
