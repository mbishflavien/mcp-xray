// Package findings defines the result types every probe reports into.
package findings

import (
	"encoding/json"
	"fmt"
)

// Severity ranks how serious a Finding is, most severe first.
type Severity int

const (
	Info Severity = iota
	Low
	Medium
	High
	Critical
)

func (s Severity) String() string {
	switch s {
	case Critical:
		return "critical"
	case High:
		return "high"
	case Medium:
		return "medium"
	case Low:
		return "low"
	default:
		return "info"
	}
}

// ParseSeverity parses a Severity's String() form back into a Severity.
func ParseSeverity(s string) (Severity, error) {
	switch s {
	case "critical":
		return Critical, nil
	case "high":
		return High, nil
	case "medium":
		return Medium, nil
	case "low":
		return Low, nil
	case "info":
		return Info, nil
	default:
		return 0, fmt.Errorf("unknown severity %q", s)
	}
}

// MarshalJSON renders a Severity as its readable name (e.g. "high")
// rather than its underlying int, so JSON reports are self-describing.
func (s Severity) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

// UnmarshalJSON parses a Severity from its readable name.
func (s *Severity) UnmarshalJSON(data []byte) error {
	var name string
	if err := json.Unmarshal(data, &name); err != nil {
		return err
	}
	parsed, err := ParseSeverity(name)
	if err != nil {
		return err
	}
	*s = parsed
	return nil
}

// Finding is one probe result against one target (a tool, resource, or the
// server as a whole).
type Finding struct {
	ProbeID string `json:"probeId"`
	// Kind is a short, stable machine-readable label for what specific
	// check produced this Finding (e.g. "sql_injection", "rate_limit"),
	// distinct from the free-text Title. Reports that group or map
	// findings (e.g. SARIF rule ids) should key off Kind, not Title.
	Kind     string   `json:"kind,omitempty"`
	Severity Severity `json:"severity"`
	Title    string   `json:"title"`
	Detail   string   `json:"detail,omitempty"`
	Target   string   `json:"target,omitempty"`
	Evidence string   `json:"evidence,omitempty"`
}
