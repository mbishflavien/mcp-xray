// Package promptinjection scans a tool's own response text for content
// shaped like an attempt to hijack whatever LLM reads that output next
// (indirect, "tool poisoning" prompt injection) - override phrases, forged
// chat-template delimiters, exfiltration directives, or invisible Unicode
// tricks.
//
// Unlike schemafuzz/authbypass/ratelimit, nothing here parses a tool's
// JSON Schema, so it doesn't run sandboxed as WASI: there's no
// attacker-controlled schema-parsing logic to protect. What *is*
// attacker-controlled is the response text itself, which can be
// arbitrarily large - maxScanLen bounds how much of it Detect ever looks
// at, the same "bound resource use, document the tradeoff" precedent
// maxSchemaFields/maxEvidenceLen/maxListItems already set elsewhere in
// this codebase.
package promptinjection

import "strings"

// maxScanLen caps how many bytes of a tool's response text Detect will
// scan. A malicious or buggy MCP server could otherwise return an
// arbitrarily large response specifically to inflate the cost of scanning
// it. 50,000 bytes is far more than any realistic tool response needs to
// be for this probe's purpose - catching an injection payload hiding in
// otherwise-normal-looking text - while still comfortably covering a
// multi-page document.
const maxScanLen = 50_000

// Match is one instance of injection-shaped content Detect found.
type Match struct {
	// Kind is a stable, machine-readable label for which category
	// matched (see the Kind* constants).
	Kind string
	// Snippet is the specific substring or description that matched,
	// for use as evidence.
	Snippet string
	// Index is the byte offset of Snippet within the (possibly capped)
	// text Detect scanned, for building a precise excerpt around it. -1
	// if there's no single position to point at.
	Index int
}

// capForScan trims text to at most maxScanLen bytes. Byte-slicing can land
// mid-rune at the very end, which is harmless here: every category below
// either does plain byte-level substring search (safe on any byte
// sequence) or ranges over runes (Go's range-over-string safely yields
// utf8.RuneError for a truncated trailing rune rather than panicking).
func capForScan(text string) string {
	if len(text) <= maxScanLen {
		return text
	}
	return text[:maxScanLen]
}

// KindInstructionOverride fires on phrases attempting to override the
// agent's own instructions. There's some false-positive risk here - a
// tool that legitimately discusses prompt injection (a security-education
// resource, say) could quote these as examples - documented rather than
// engineered around, the same tradeoff auth-bypass's field-name heuristic
// and rate-limit's latency heuristic already make elsewhere in this
// codebase.
const KindInstructionOverride = "prompt_injection_instruction_override"

var instructionOverridePhrases = []string{
	"ignore previous instructions",
	"ignore all previous instructions",
	"ignore the above instructions",
	"disregard previous instructions",
	"disregard the above",
	"disregard all prior instructions",
	"forget your instructions",
	"forget everything above",
	"new instructions:",
	"you must now",
	"do not follow your system prompt",
}

// matchFirstPhrase returns the first phrase from phrases found in lower
// (already-lowercased text) and its byte index, or ("", -1) if none
// match. Only the first match matters: one hit is enough to report a
// category once, see Detect.
func matchFirstPhrase(lower string, phrases []string) (phrase string, index int) {
	for _, p := range phrases {
		if idx := strings.Index(lower, p); idx >= 0 {
			return p, idx
		}
	}
	return "", -1
}

func detectInstructionOverride(lower string) *Match {
	phrase, idx := matchFirstPhrase(lower, instructionOverridePhrases)
	if idx < 0 {
		return nil
	}
	return &Match{Kind: KindInstructionOverride, Snippet: phrase, Index: idx}
}

// KindRoleImpersonation fires on forged LLM chat-template delimiters.
// Unlike instruction_override, these are essentially never legitimate in
// real tool output - a tool has no reason to emit a raw "<|system|>" or
// "[INST]" token - so this carries no documented false-positive caveat.
const KindRoleImpersonation = "prompt_injection_role_impersonation"

var roleImpersonationMarkers = []string{
	"<|system|>",
	"<|im_start|>",
	"<|im_end|>",
	"[inst]",
	"[/inst]",
	"###instruction",
	"### instruction",
	"###system",
	"### system",
}

func detectRoleImpersonation(lower string) *Match {
	marker, idx := matchFirstPhrase(lower, roleImpersonationMarkers)
	if idx < 0 {
		return nil
	}
	return &Match{Kind: KindRoleImpersonation, Snippet: marker, Index: idx}
}
