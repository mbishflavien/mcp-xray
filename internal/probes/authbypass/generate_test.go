package authbypass

import (
	"encoding/json"
	"fmt"
	"testing"
)

func kindsFor(t *testing.T, toolName string, schema string) map[string]any {
	t.Helper()
	mutations, errMsg := Generate(toolName, json.RawMessage(schema))
	if errMsg != "" {
		t.Fatalf("Generate() error: %s", errMsg)
	}
	byKind := make(map[string]any, len(mutations))
	for _, m := range mutations {
		byKind[m.Kind] = m.Args
	}
	return byKind
}

func TestGenerateIdentityField(t *testing.T) {
	byKind := kindsFor(t, "get_account", `{
		"type": "object",
		"properties": {"account_id": {"type": "string"}}
	}`)
	args, ok := byKind["auth_bypass_identity"].(map[string]any)
	if !ok {
		t.Fatalf("expected an auth_bypass_identity mutation, got %v", byKind)
	}
	if args["account_id"] != "0" {
		t.Errorf("account_id = %v, want \"0\"", args["account_id"])
	}
}

func TestGenerateIdentityFieldNumberType(t *testing.T) {
	byKind := kindsFor(t, "get_account", `{
		"type": "object",
		"properties": {"user_id": {"type": "integer"}}
	}`)
	args, ok := byKind["auth_bypass_identity"].(map[string]any)
	if !ok {
		t.Fatalf("expected an auth_bypass_identity mutation, got %v", byKind)
	}
	if args["user_id"] != 0 {
		t.Errorf("user_id = %v, want 0", args["user_id"])
	}
}

func TestGenerateIdentityFieldUnhandledTypeSkipped(t *testing.T) {
	// "owner" declared as a boolean doesn't fit any adversarial value this
	// category knows how to produce, so it should be skipped rather than
	// guessed at.
	byKind := kindsFor(t, "get_account", `{
		"type": "object",
		"properties": {"owner": {"type": "boolean"}}
	}`)
	if _, ok := byKind["auth_bypass_identity"]; ok {
		t.Errorf("expected no auth_bypass_identity mutation for a boolean-typed identity field, got %v", byKind)
	}
}

func TestGeneratePrivilegeField(t *testing.T) {
	byKind := kindsFor(t, "get_account", `{
		"type": "object",
		"properties": {"role": {"type": "string"}}
	}`)
	args, ok := byKind["auth_bypass_privilege"].(map[string]any)
	if !ok {
		t.Fatalf("expected an auth_bypass_privilege mutation, got %v", byKind)
	}
	if args["role"] != "admin" {
		t.Errorf("role = %v, want \"admin\"", args["role"])
	}
}

func TestGeneratePrivilegeFieldBooleanType(t *testing.T) {
	byKind := kindsFor(t, "get_account", `{
		"type": "object",
		"properties": {"is_admin": {"type": "boolean"}}
	}`)
	args, ok := byKind["auth_bypass_privilege"].(map[string]any)
	if !ok {
		t.Fatalf("expected an auth_bypass_privilege mutation, got %v", byKind)
	}
	if args["is_admin"] != true {
		t.Errorf("is_admin = %v, want true", args["is_admin"])
	}
}

func TestGenerateCredentialField(t *testing.T) {
	byKind := kindsFor(t, "get_account", `{
		"type": "object",
		"properties": {"token": {"type": "string"}}
	}`)
	args, ok := byKind["auth_bypass_credential"].(map[string]any)
	if !ok {
		t.Fatalf("expected an auth_bypass_credential mutation, got %v", byKind)
	}
	if args["token"] != "" {
		t.Errorf("token = %q, want empty string", args["token"])
	}
}

// TestGenerateAuthorFieldNotMatched confirms "author" doesn't false-positive
// as a credential field via a bare "auth" substring match.
func TestGenerateAuthorFieldNotMatched(t *testing.T) {
	byKind := kindsFor(t, "write_post", `{
		"type": "object",
		"properties": {"author": {"type": "string"}}
	}`)
	if len(byKind) != 0 {
		t.Errorf("expected no mutations for a tool with only an \"author\" field, got %v", byKind)
	}
}

func TestGenerateNoMatchingFields(t *testing.T) {
	byKind := kindsFor(t, "greet", `{
		"type": "object",
		"properties": {"name": {"type": "string"}}
	}`)
	if len(byKind) != 0 {
		t.Errorf("expected no mutations for a tool with no authorization-shaped fields, got %v", byKind)
	}
}

func TestGenerateBaseArgsFillsOtherRequiredFields(t *testing.T) {
	byKind := kindsFor(t, "get_account", `{
		"type": "object",
		"properties": {
			"account_id": {"type": "string"},
			"note": {"type": "string"}
		},
		"required": ["account_id", "note"]
	}`)
	args, ok := byKind["auth_bypass_identity"].(map[string]any)
	if !ok {
		t.Fatalf("expected an auth_bypass_identity mutation, got %v", byKind)
	}
	if args["note"] != "mcp-xray-probe" {
		t.Errorf("note = %v, want the base placeholder (untouched by this mutation)", args["note"])
	}
}

// TestGenerateCapsAnAdversarialSchema confirms a schema with far more
// properties than any reasonable tool would declare doesn't blow up
// Generate's output, for the same reason internal/probes/schemafuzz caps
// its own fields.
func TestGenerateCapsAnAdversarialSchema(t *testing.T) {
	const propertyCount = 10_000

	properties := make(map[string]map[string]string, propertyCount)
	for i := range propertyCount {
		name := fmt.Sprintf("user_id_%d", i)
		properties[name] = map[string]string{"type": "string"}
	}
	schema, err := json.Marshal(map[string]any{
		"type":       "object",
		"properties": properties,
	})
	if err != nil {
		t.Fatalf("marshal adversarial schema: %v", err)
	}

	mutations, errMsg := Generate("get_account", schema)
	if errMsg != "" {
		t.Fatalf("Generate() error: %s", errMsg)
	}
	if len(mutations) > maxSchemaFields {
		t.Errorf("Generate() produced %d mutations from %d properties, want at most %d",
			len(mutations), propertyCount, maxSchemaFields)
	}
}

func TestGenerateInvalidSchema(t *testing.T) {
	_, errMsg := Generate("get_account", json.RawMessage(`not json`))
	if errMsg == "" {
		t.Error("Generate() with invalid schema should return an error message")
	}
}
