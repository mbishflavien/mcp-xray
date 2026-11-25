package report

import (
	"encoding/json"
	"io"

	"github.com/mbishflavien/mcp-xray/findings"
)

// SARIF (Static Analysis Results Interchange Format) is what GitHub code
// scanning and most CI systems in this space expect. mcp-xray's findings
// describe live tool-call behavior, not a source location, so there is no
// natural physicalLocation to report - we use logicalLocations (the tool
// name) instead of fabricating a fake file path. GitHub's UI renders
// these results without a source-line anchor, which is an accepted
// limitation of reporting on runtime behavior, not a bug to chase here.
type sarifWriter struct{}

// SARIF returns a Writer that renders a Result as a minimal SARIF 2.1.0
// log, suitable for `github/codeql-action/upload-sarif` or similar.
func SARIF() Writer { return sarifWriter{} }

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	LogicalLocations []sarifLogicalLocation `json:"logicalLocations"`
}

type sarifLogicalLocation struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
}

func sarifLevel(sev findings.Severity) string {
	switch sev {
	case findings.Critical, findings.High:
		return "error"
	case findings.Medium:
		return "warning"
	default: // Low, Info
		return "note"
	}
}

func sarifRuleID(f findings.Finding) string {
	if f.Kind != "" {
		return f.ProbeID + "/" + f.Kind
	}
	return f.ProbeID
}

func (sarifWriter) Write(w io.Writer, r Result) error {
	results := make([]sarifResult, 0, len(r.Findings))
	for _, f := range r.Findings {
		message := f.Title
		if f.Detail != "" {
			message += ": " + f.Detail
		}
		results = append(results, sarifResult{
			RuleID:  sarifRuleID(f),
			Level:   sarifLevel(f.Severity),
			Message: sarifMessage{Text: message},
			Locations: []sarifLocation{{
				LogicalLocations: []sarifLogicalLocation{{Name: f.Target, Kind: "function"}},
			}},
		})
	}

	log := sarifLog{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool:    sarifTool{Driver: sarifDriver{Name: "mcp-xray"}},
			Results: results,
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}
