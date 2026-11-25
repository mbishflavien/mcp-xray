package report

import (
	"fmt"
	"io"
)

type textWriter struct{}

// Text returns a Writer that renders a human-readable report.
func Text() Writer { return textWriter{} }

func (textWriter) Write(w io.Writer, r Result) error {
	if _, err := fmt.Fprintf(w, "%s %s\n", r.ServerName, r.ServerVersion); err != nil {
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
		if _, err := fmt.Fprintf(w, "[%s] %s: %s\n", f.Severity, f.Target, f.Title); err != nil {
			return err
		}
		if f.Detail != "" {
			if _, err := fmt.Fprintf(w, "    %s\n", f.Detail); err != nil {
				return err
			}
		}
		if f.Evidence != "" {
			if _, err := fmt.Fprintf(w, "    evidence: %s\n", f.Evidence); err != nil {
				return err
			}
		}
	}
	return nil
}
