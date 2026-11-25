// Package report turns a scan's []findings.Finding into something a
// human or CI system can read: plain text, JSON, or SARIF, plus the exit
// code a CLI should return for a given --fail-on threshold.
package report

import (
	"fmt"
	"io"

	"github.com/mbishflavien/mcp-xray/findings"
)

// Result is everything one scan produced, ready to write out.
type Result struct {
	ServerName    string             `json:"serverName"`
	ServerVersion string             `json:"serverVersion"`
	Findings      []findings.Finding `json:"findings"`
}

// Writer renders a Result to w in some format.
type Writer interface {
	Write(w io.Writer, r Result) error
}

// Format names an output format a CLI user can ask for.
type Format string

const (
	FormatText  Format = "text"
	FormatJSON  Format = "json"
	FormatSARIF Format = "sarif"
)

// ParseFormat parses a --format flag value.
func ParseFormat(s string) (Format, error) {
	switch Format(s) {
	case FormatText, FormatJSON, FormatSARIF:
		return Format(s), nil
	default:
		return "", fmt.Errorf("unknown format %q: want one of text, json, sarif", s)
	}
}

// WriterFor returns the Writer for a Format.
func WriterFor(f Format) (Writer, error) {
	switch f {
	case FormatText:
		return Text(), nil
	case FormatJSON:
		return JSON(), nil
	case FormatSARIF:
		return SARIF(), nil
	default:
		return nil, fmt.Errorf("unknown format %q", f)
	}
}

// ParseFailOn parses a --fail-on flag value. "none" (or "") reports
// ok=false so callers can distinguish "no threshold was set" from an
// actual severity.
func ParseFailOn(s string) (sev findings.Severity, ok bool, err error) {
	if s == "" || s == "none" {
		return 0, false, nil
	}
	sev, err = findings.ParseSeverity(s)
	if err != nil {
		return 0, false, fmt.Errorf("%w (or \"none\")", err)
	}
	return sev, true, nil
}

// MaxSeverity returns the highest severity among fs, and false if fs is
// empty.
func MaxSeverity(fs []findings.Finding) (findings.Severity, bool) {
	if len(fs) == 0 {
		return 0, false
	}
	max := fs[0].Severity
	for _, f := range fs[1:] {
		if f.Severity > max {
			max = f.Severity
		}
	}
	return max, true
}

// ExitCode returns the process exit code for a scan: 1 if failOnSet and
// the highest finding severity is at or above failOn, 0 otherwise. It
// takes no action itself (no os.Exit) so it stays testable.
func ExitCode(fs []findings.Finding, failOn findings.Severity, failOnSet bool) int {
	if !failOnSet {
		return 0
	}
	max, ok := MaxSeverity(fs)
	if !ok {
		return 0
	}
	if max >= failOn {
		return 1
	}
	return 0
}
