package ratelimit

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/mbishflavien/mcp-xray/internal/probes/schemashape"
)

func TestGenerateReturnsExactlyOneBaselineMutation(t *testing.T) {
	mutations, errMsg := Generate("greet", json.RawMessage(`{
		"type": "object",
		"properties": {
			"name": {"type": "string"},
			"age": {"type": "number"},
			"active": {"type": "boolean"}
		}
	}`))
	if errMsg != "" {
		t.Fatalf("Generate() error: %s", errMsg)
	}
	if len(mutations) != 1 {
		t.Fatalf("Generate() returned %d mutations, want exactly 1", len(mutations))
	}

	args := mutations[0].Args
	if args["name"] != "mcp-xray-probe" || args["age"] != 1 || args["active"] != true {
		t.Errorf("baseline args = %v, want every declared field filled with a valid-looking placeholder", args)
	}
	if mutations[0].Kind != "rate_limit_baseline" {
		t.Errorf("Kind = %q, want rate_limit_baseline", mutations[0].Kind)
	}
}

func TestGenerateNoPropertiesStillProducesAnEmptyBaseline(t *testing.T) {
	mutations, errMsg := Generate("no_args_tool", json.RawMessage(`{"type": "object"}`))
	if errMsg != "" {
		t.Fatalf("Generate() error: %s", errMsg)
	}
	if len(mutations) != 1 {
		t.Fatalf("Generate() returned %d mutations, want exactly 1", len(mutations))
	}
	if len(mutations[0].Args) != 0 {
		t.Errorf("baseline args = %v, want empty for a tool with no properties", mutations[0].Args)
	}
}

// TestGenerateCapsAnAdversarialSchema confirms a schema with far more
// properties than any reasonable tool would declare doesn't blow up the
// baseline it builds, for the same reason schema-fuzz and auth-bypass cap
// their own fields via schemashape.Cap.
func TestGenerateCapsAnAdversarialSchema(t *testing.T) {
	const propertyCount = 10_000

	properties := make(map[string]map[string]string, propertyCount)
	for i := range propertyCount {
		properties[fmt.Sprintf("field_%d", i)] = map[string]string{"type": "string"}
	}
	schema, err := json.Marshal(map[string]any{
		"type":       "object",
		"properties": properties,
	})
	if err != nil {
		t.Fatalf("marshal adversarial schema: %v", err)
	}

	mutations, errMsg := Generate("greet", schema)
	if errMsg != "" {
		t.Fatalf("Generate() error: %s", errMsg)
	}
	if len(mutations) != 1 {
		t.Fatalf("Generate() returned %d mutations, want exactly 1", len(mutations))
	}
	if len(mutations[0].Args) > schemashape.MaxFields {
		t.Errorf("baseline has %d args, want at most %d", len(mutations[0].Args), schemashape.MaxFields)
	}
}

func TestGenerateInvalidSchema(t *testing.T) {
	_, errMsg := Generate("greet", json.RawMessage(`not json`))
	if errMsg == "" {
		t.Error("Generate() with invalid schema should return an error message")
	}
}
