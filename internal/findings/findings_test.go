package findings

import "testing"

func TestSeverityString(t *testing.T) {
	cases := []struct {
		severity Severity
		want     string
	}{
		{Critical, "critical"},
		{High, "high"},
		{Medium, "medium"},
		{Low, "low"},
		{Info, "info"},
	}
	for _, c := range cases {
		if got := c.severity.String(); got != c.want {
			t.Errorf("Severity(%d).String() = %q, want %q", c.severity, got, c.want)
		}
	}
}
