package report

import (
	"fmt"
	"io"
	"strings"
	"unicode"
)

type textWriter struct{}

// Text returns a Writer that renders a human-readable report.
func Text() Writer { return textWriter{} }

func (textWriter) Write(w io.Writer, r Result) error {
	if _, err := fmt.Fprintf(w, "%s %s\n", sanitizeForTerminal(r.ServerName), sanitizeForTerminal(r.ServerVersion)); err != nil {
		return err
	}
	if len(r.Findings) == 0 {
		_, err := fmt.Fprintln(w, "no findings")
		return err
	}
	if _, err := fmt.Fprintf(w, "%d finding(s):\n\n", len(r.Findings)); err != nil {
		return err
	}
	for _, f := range r.Findings {
		if _, err := fmt.Fprintf(w, "[%s] %s: %s\n", f.Severity, sanitizeForTerminal(f.Target), sanitizeForTerminal(f.Title)); err != nil {
			return err
		}
		if f.Detail != "" {
			if _, err := fmt.Fprintf(w, "    %s\n", sanitizeForTerminal(f.Detail)); err != nil {
				return err
			}
		}
		if f.Evidence != "" {
			if _, err := fmt.Fprintf(w, "    evidence: %s\n", sanitizeForTerminal(f.Evidence)); err != nil {
				return err
			}
		}
	}
	return nil
}

// sanitizeForTerminal strips control characters (ANSI/terminal escape
// sequences, embedded newlines, etc.) from text before it's printed.
// ServerName/ServerVersion/Target/Evidence all ultimately come from the
// MCP server mcp-xray is scanning - a server under test is exactly the
// thing this tool assumes may be malicious or compromised, and printing
// its output verbatim to a terminal would let it inject escape sequences
// (which some terminals interpret as commands, e.g. OSC 52 clipboard
// writes) or forge fake-looking additional report lines via embedded
// newlines. JSON and SARIF output don't need this: encoding/json already
// escapes every control character.
func sanitizeForTerminal(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
}
