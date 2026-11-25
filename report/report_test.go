package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/mbishflavien/mcp-xray/findings"
)

func sampleResult() Result {
	return Result{
		ServerName:    "example-server",
		ServerVersion: "1.0.0",
		Findings: []findings.Finding{
			{
				ProbeID:  "schema-fuzz",
				Kind:     "null_byte_injection",
				Severity: findings.High,
				Title:    "null_byte_injection: crash",
				Detail:   "send a string with an embedded null byte for \"data\"",
				Target:   "process",
				Evidence: "connection closed",
			},
		},
	}
}

func TestTextWriter(t *testing.T) {
	var buf bytes.Buffer
	if err := Text().Write(&buf, sampleResult()); err != nil {
		t.Fatalf("Write() error: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"example-server", "process", "null_byte_injection: crash", "connection closed"} {
		if !strings.Contains(out, want) {
			t.Errorf("text report missing %q, got:\n%s", want, out)
		}
	}
}

// TestTextWriterSanitizesAttackerControlledFields confirms a malicious
// target server can't inject terminal escape sequences or forge fake
// report lines via embedded control characters/newlines in its own
// name, a tool name, or a tool response (Evidence) - mcp-xray's own
// threat model is that the server under test may be malicious.
func TestTextWriterSanitizesAttackerControlledFields(t *testing.T) {
	r := Result{
		ServerName:    "evil\x1b[31mserver",
		ServerVersion: "1.0.0",
		Findings: []findings.Finding{{
			ProbeID:  "schema-fuzz",
			Severity: findings.Low,
			Title:    "oversized_string: accepted_invalid",
			Target:   "tool\x1b]52;c;ZWNobyBwd25lZA==\x07name",
			Evidence: "line one\n[critical] fake-tool: fabricated finding\nline two",
		}},
	}

	var buf bytes.Buffer
	if err := Text().Write(&buf, r); err != nil {
		t.Fatalf("Write() error: %v", err)
	}
	out := buf.String()

	if strings.ContainsRune(out, 0x1b) {
		t.Errorf("text report contains a raw ESC byte, want it stripped:\n%q", out)
	}
	if strings.Contains(out, "fake-tool") == false {
		t.Fatal("sanity check failed: expected text to still be present, just without the newlines around it")
	}
	// The embedded newlines in Evidence must not survive as newlines -
	// otherwise the fabricated "[critical] fake-tool: ..." line reads as
	// its own independent report entry rather than evidence text.
	for line := range strings.SplitSeq(strings.TrimRight(out, "\n"), "\n") {
		if strings.HasPrefix(line, "[critical]") {
			t.Errorf("a line injected via Evidence's embedded newline appears as its own report entry: %q", line)
		}
	}
}

func TestTextWriterNoFindings(t *testing.T) {
	var buf bytes.Buffer
	r := sampleResult()
	r.Findings = nil
	if err := Text().Write(&buf, r); err != nil {
		t.Fatalf("Write() error: %v", err)
	}
	if !strings.Contains(buf.String(), "no findings") {
		t.Errorf("expected a 'no findings' line, got:\n%s", buf.String())
	}
}

func TestJSONWriterRoundTrips(t *testing.T) {
	var buf bytes.Buffer
	if err := JSON().Write(&buf, sampleResult()); err != nil {
		t.Fatalf("Write() error: %v", err)
	}

	var got Result
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("json.Unmarshal() error: %v\noutput:\n%s", err, buf.String())
	}
	if len(got.Findings) != 1 || got.Findings[0].Severity != findings.High {
		t.Errorf("round-tripped findings = %+v, want severity High", got.Findings)
	}
	if !strings.Contains(buf.String(), `"severity": "high"`) {
		t.Errorf("expected severity to serialize as the string \"high\", got:\n%s", buf.String())
	}
}

func TestSARIFWriterIsValidAndLevelsMap(t *testing.T) {
	result := sampleResult()
	result.Findings = append(result.Findings,
		findings.Finding{ProbeID: "p", Severity: findings.Medium, Title: "medium one", Target: "t"},
		findings.Finding{ProbeID: "p", Severity: findings.Low, Title: "low one", Target: "t"},
	)

	var buf bytes.Buffer
	if err := SARIF().Write(&buf, result); err != nil {
		t.Fatalf("Write() error: %v", err)
	}

	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("SARIF output is not valid JSON: %v\n%s", err, buf.String())
	}

	runs := doc["runs"].([]any)
	results := runs[0].(map[string]any)["results"].([]any)
	if len(results) != 3 {
		t.Fatalf("results length = %d, want 3", len(results))
	}

	wantLevels := []string{"error", "warning", "note"}
	for i, want := range wantLevels {
		got := results[i].(map[string]any)["level"]
		if got != want {
			t.Errorf("results[%d].level = %v, want %q", i, got, want)
		}
	}
}

func TestParseFailOn(t *testing.T) {
	if _, ok, err := ParseFailOn(""); err != nil || ok {
		t.Errorf(`ParseFailOn("") = ok=%v err=%v, want ok=false err=nil`, ok, err)
	}
	if _, ok, err := ParseFailOn("none"); err != nil || ok {
		t.Errorf(`ParseFailOn("none") = ok=%v err=%v, want ok=false err=nil`, ok, err)
	}
	sev, ok, err := ParseFailOn("high")
	if err != nil || !ok || sev != findings.High {
		t.Errorf(`ParseFailOn("high") = %v, %v, %v, want High, true, nil`, sev, ok, err)
	}
	if _, _, err := ParseFailOn("severe"); err == nil {
		t.Error(`ParseFailOn("severe") should error on an unknown severity`)
	}
}

func TestExitCode(t *testing.T) {
	highFinding := []findings.Finding{{Severity: findings.High}}
	lowFinding := []findings.Finding{{Severity: findings.Low}}

	cases := []struct {
		name      string
		fs        []findings.Finding
		failOn    findings.Severity
		failOnSet bool
		want      int
	}{
		{"no threshold set, findings present", highFinding, findings.High, false, 0},
		{"no findings at all", nil, findings.Low, true, 0},
		{"finding at or above threshold", highFinding, findings.High, true, 1},
		{"finding above threshold", highFinding, findings.Medium, true, 1},
		{"finding below threshold", lowFinding, findings.High, true, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ExitCode(tc.fs, tc.failOn, tc.failOnSet); got != tc.want {
				t.Errorf("ExitCode() = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestWriterForAndParseFormat(t *testing.T) {
	for _, s := range []string{"text", "json", "sarif"} {
		f, err := ParseFormat(s)
		if err != nil {
			t.Fatalf("ParseFormat(%q) error: %v", s, err)
		}
		if _, err := WriterFor(f); err != nil {
			t.Errorf("WriterFor(%q) error: %v", f, err)
		}
	}
	if _, err := ParseFormat("yaml"); err == nil {
		t.Error(`ParseFormat("yaml") should error on an unsupported format`)
	}
}
