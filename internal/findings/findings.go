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
	ProbeID  string
	Severity Severity
	Title    string
	Detail   string
	Target   string
	Evidence string
}
