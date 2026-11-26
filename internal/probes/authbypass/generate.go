// Package authbypass generates forged identity, privilege, and credential
// payloads from a tool's JSON Schema. The logic lives here as plain,
// natively-testable Go; cmd/probes/authbypass wraps it as a stdin/stdout
// program so it can also run sandboxed as WASI.
package authbypass

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/mbishflavien/mcp-xray/internal/probeproto"
)

// objectSchema covers the subset of JSON Schema this probe understands: a
// flat object with typed properties. Nested schemas, $ref, oneOf/anyOf, and
// array item schemas are not resolved; properties using them are skipped
// rather than guessed at - the same limitation internal/probes/schemafuzz
// states for the same reason.
type objectSchema struct {
	Type       string                  `json:"type"`
	Properties map[string]propertySpec `json:"properties"`
}

type propertySpec struct {
	Type string `json:"type"`
}

// maxSchemaFields caps how many properties Generate will consider, for the
// same reason internal/probes/schemafuzz caps its own fields: a malicious
// or buggy MCP server could otherwise advertise an enormous schema to
// inflate the scan's memory and call count.
const maxSchemaFields = 200

// category is one kind of authorization-shaped field this probe looks for.
type category struct {
	kind  string
	names []string
	// value returns the adversarial value to send for this category given
	// a property's declared JSON type, and whether that type is handled at
	// all for this category.
	value func(propType string) (value any, ok bool)
}

var categories = []category{
	{
		// identity (IDOR risk): a field naming whose record this call acts
		// on. mcp-xray has no way to know the *correct* id, so it tries an
		// implausible one and checks whether the server does the
		// privileged thing anyway instead of rejecting it.
		kind: "auth_bypass_identity",
		names: []string{
			"user_id", "userid", "account_id", "accountid",
			"owner_id", "ownerid", "owner",
			"tenant_id", "tenantid", "org_id", "orgid", "organization_id",
			"customer_id", "customerid",
		},
		value: func(propType string) (any, bool) {
			switch propType {
			case "string":
				return "0", true
			case "number", "integer":
				return 0, true
			default:
				return nil, false
			}
		},
	},
	{
		// privilege (escalation risk): a field claiming the caller's own
		// role or access level, which a server must verify independently
		// rather than trust at face value.
		kind:  "auth_bypass_privilege",
		names: []string{"role", "is_admin", "isadmin", "admin", "permission", "scope", "access_level", "privilege"},
		value: func(propType string) (any, bool) {
			switch propType {
			case "string":
				return "admin", true
			case "boolean":
				return true, true
			default:
				return nil, false
			}
		},
	},
	{
		// credential (forged/blank credential risk): a field carrying
		// whatever token or session the server is supposed to check.
		// Deliberately not a bare "auth" substring match, which would
		// false-positive on "author".
		kind: "auth_bypass_credential",
		names: []string{
			"token", "api_key", "apikey", "session_token", "session_id", "sessionid",
			"credential", "secret", "access_token", "auth_token",
		},
		value: func(propType string) (any, bool) {
			if propType == "string" {
				return "", true
			}
			return nil, false
		},
	},
}

// matchCategory returns the category whose names list contains propName
// (case-insensitive), or nil if none match.
func matchCategory(propName string) *category {
	lower := strings.ToLower(propName)
	for i := range categories {
		if slices.Contains(categories[i].names, lower) {
			return &categories[i]
		}
	}
	return nil
}

// Generate returns the mutations to try for the given tool and schema, or
// an error message (not a Go error, since this crosses the WASI boundary as
// plain JSON) if the schema can't be parsed. A tool whose schema has no
// identity/privilege/credential-shaped field produces no mutations at all -
// unlike schema-fuzz, which fuzzes every tool unconditionally, this probe
// only has something to say about a tool that looks like it carries an
// authorization decision.
func Generate(toolName string, schema json.RawMessage) ([]probeproto.Mutation, string) {
	var s objectSchema
	if err := json.Unmarshal(schema, &s); err != nil {
		return nil, fmt.Sprintf("parse schema: %v", err)
	}
	s = capSchema(s)

	base := baseArgs(s)
	var mutations []probeproto.Mutation

	for name, prop := range s.Properties {
		cat := matchCategory(name)
		if cat == nil {
			continue
		}
		value, ok := cat.value(prop.Type)
		if !ok {
			continue
		}
		args := cloneArgs(base)
		args[name] = value
		mutations = append(mutations, probeproto.Mutation{
			ID:          fmt.Sprintf("%s/%s/%s", toolName, strings.ReplaceAll(cat.kind, "_", "-"), name),
			Kind:        cat.kind,
			Description: fmt.Sprintf("send %q = %v for %q, a field that looks like it carries an authorization decision", name, value, name),
			Args:        args,
		})
	}

	return mutations, ""
}

// capSchema trims an oversized schema down to maxSchemaFields properties.
// Map iteration order is unspecified, so which fields survive is arbitrary -
// that's fine, this is a bound on scanner resource use, not a guarantee of
// which fields get tested.
func capSchema(s objectSchema) objectSchema {
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
