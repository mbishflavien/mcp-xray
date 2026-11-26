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
	for _, want := range []string{
		"missing_required", "oversized_string", "path_traversal", "mass_assignment",
		"null_byte_injection", "sql_injection", "shell_injection", "template_injection",
	} {
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

func TestAuthBypassMutationsEndToEnd(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	schema := json.RawMessage(`{
		"type": "object",
		"properties": {
			"account_id": {"type": "string"},
			"role": {"type": "string"}
		}
	}`)

	mutations, err := AuthBypassMutations(ctx, "get_account", schema)
	if err != nil {
		t.Fatalf("AuthBypassMutations() error: %v", err)
	}

	kinds := make(map[string]bool)
	for _, m := range mutations {
		kinds[m.Kind] = true
	}
	for _, want := range []string{"auth_bypass_identity", "auth_bypass_privilege"} {
		if !kinds[want] {
			t.Errorf("mutations missing kind %q; got %v", want, mutations)
		}
	}
}

func TestAuthBypassMutationsInvalidSchema(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := AuthBypassMutations(ctx, "get_account", json.RawMessage(`not json`))
	if err == nil {
		t.Error("AuthBypassMutations() with invalid schema should return an error")
	}
}

func TestRateLimitBaselineEndToEnd(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	schema := json.RawMessage(`{
		"type": "object",
		"properties": {"name": {"type": "string"}}
	}`)

	args, err := RateLimitBaseline(ctx, "greet", schema)
	if err != nil {
		t.Fatalf("RateLimitBaseline() error: %v", err)
	}
	if args["name"] != "mcp-xray-probe" {
		t.Errorf("baseline args = %v, want name filled with a valid-looking placeholder", args)
	}
}

func TestRateLimitBaselineInvalidSchema(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := RateLimitBaseline(ctx, "greet", json.RawMessage(`not json`))
	if err == nil {
		t.Error("RateLimitBaseline() with invalid schema should return an error")
	}
}
