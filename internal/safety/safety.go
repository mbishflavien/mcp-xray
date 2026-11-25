// Package safety implements the default probe.SafetyPolicy: a keyword
// gate that blocks calling a tool whose name suggests it's destructive,
// so a probe doesn't fuzz a tool literally named delete_all_records.
package safety

import (
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// DefaultKeywords are the tool-name substrings KeywordPolicy blocks by
// default, matched case-insensitively.
var DefaultKeywords = []string{
	"delete", "drop", "destroy", "remove", "purge",
	"truncate", "wipe", "erase", "format",
}

// KeywordPolicy blocks a tool when its name contains one of Keywords,
// unless the tool is in Allowlist or AllowAll is set.
type KeywordPolicy struct {
	Keywords  []string
	Allowlist map[string]bool
	AllowAll  bool
}

// NewKeywordPolicy returns a KeywordPolicy using DefaultKeywords.
func NewKeywordPolicy() *KeywordPolicy {
	return &KeywordPolicy{Keywords: DefaultKeywords}
}

// Allow implements probe.SafetyPolicy.
func (p *KeywordPolicy) Allow(tool *mcp.Tool) (bool, string) {
	if p.AllowAll || p.Allowlist[tool.Name] {
		return true, ""
	}
	name := strings.ToLower(tool.Name)
	for _, keyword := range p.Keywords {
		if strings.Contains(name, keyword) {
			return false, fmt.Sprintf("tool name contains %q", keyword)
		}
	}
	return true, ""
}
