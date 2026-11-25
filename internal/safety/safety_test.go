package safety

import (
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestKeywordPolicyAllow(t *testing.T) {
	cases := []struct {
		name     string
		toolName string
		want     bool
	}{
		{"plain lookup is allowed", "get_weather", true},
		{"delete is blocked", "delete_all_records", false},
		{"DROP is blocked case-insensitively", "DROP_TABLE", false},
		{"destroy is blocked", "destroy_instance", false},
		{"purge is blocked", "purge_cache", false},
		{"a word that merely contains the keyword is still blocked", "undelete_backup", false},
	}

	policy := NewKeywordPolicy()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ok, reason := policy.Allow(&mcp.Tool{Name: tc.toolName})
			if ok != tc.want {
				t.Errorf("Allow(%q) = (%v, %q), want ok = %v", tc.toolName, ok, reason, tc.want)
			}
			if !ok && reason == "" {
				t.Error("a blocked call should have a non-empty reason")
			}
		})
	}
}

func TestKeywordPolicyAllowlistOverride(t *testing.T) {
	policy := NewKeywordPolicy()
	policy.Allowlist = map[string]bool{"delete_draft": true}

	if ok, _ := policy.Allow(&mcp.Tool{Name: "delete_draft"}); !ok {
		t.Error("an allowlisted tool should be allowed despite the keyword match")
	}
	if ok, _ := policy.Allow(&mcp.Tool{Name: "delete_all_records"}); ok {
		t.Error("a non-allowlisted destructive tool should still be blocked")
	}
}

func TestKeywordPolicyAllowAll(t *testing.T) {
	policy := NewKeywordPolicy()
	policy.AllowAll = true

	if ok, _ := policy.Allow(&mcp.Tool{Name: "delete_all_records"}); !ok {
		t.Error("AllowAll should override every keyword match")
	}
}
