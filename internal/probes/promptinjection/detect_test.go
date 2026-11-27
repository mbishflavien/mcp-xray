package promptinjection

import (
	"strings"
	"testing"
)

func TestCapForScanLeavesShortTextUntouched(t *testing.T) {
	short := "hello world"
	if got := capForScan(short); got != short {
		t.Errorf("capForScan(%q) = %q, want it unchanged", short, got)
	}
}

func TestCapForScanTrimsAnOversizedResponse(t *testing.T) {
	huge := strings.Repeat("A", maxScanLen*2)
	got := capForScan(huge)
	if len(got) != maxScanLen {
		t.Errorf("capForScan() left %d bytes, want exactly %d", len(got), maxScanLen)
	}
}
