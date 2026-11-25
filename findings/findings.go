// Package findings defines the result types every probe reports into.
package findings

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

// Finding is one probe result against one target (a tool, resource, or the
// server as a whole).
type Finding struct {
	ProbeID string
	// Kind is a short, stable machine-readable label for what specific
	// check produced this Finding (e.g. "sql_injection", "rate_limit"),
	// distinct from the free-text Title. Reports that group or map
	// findings (e.g. SARIF rule ids) should key off Kind, not Title.
	Kind     string
	Severity Severity
	Title    string
	Detail   string
	Target   string
	Evidence string
}
