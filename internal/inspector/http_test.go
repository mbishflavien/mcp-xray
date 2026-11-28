package inspector

import "testing"

func TestParseHeaderFlag(t *testing.T) {
	name, value, err := ParseHeaderFlag("Authorization: Bearer abc123")
	if err != nil {
		t.Fatalf("ParseHeaderFlag() error: %v", err)
	}
	if name != "Authorization" || value != "Bearer abc123" {
		t.Errorf("got (%q, %q), want (%q, %q)", name, value, "Authorization", "Bearer abc123")
	}
}

func TestParseHeaderFlagTrimsSpace(t *testing.T) {
	name, value, err := ParseHeaderFlag("X-Api-Key :   secret  ")
	if err != nil {
		t.Fatalf("ParseHeaderFlag() error: %v", err)
	}
	if name != "X-Api-Key" || value != "secret" {
		t.Errorf("got (%q, %q), want (%q, %q)", name, value, "X-Api-Key", "secret")
	}
}

func TestParseHeaderFlagMissingColon(t *testing.T) {
	if _, _, err := ParseHeaderFlag("no-colon-here"); err == nil {
		t.Error("expected an error for a header with no ':' separator, got nil")
	}
}

func TestParseHeaderFlagEmptyName(t *testing.T) {
	if _, _, err := ParseHeaderFlag(": value"); err == nil {
		t.Error("expected an error for an empty header name, got nil")
	}
}

func TestParseHeaderFlagRejectsCR(t *testing.T) {
	if _, _, err := ParseHeaderFlag("X-Evil: value\r\nX-Injected: yes"); err == nil {
		t.Error("expected an error for a header value containing CRLF, got nil")
	}
}

func TestParseHeaderFlagRejectsCRInName(t *testing.T) {
	if _, _, err := ParseHeaderFlag("X-Evil\r\nX-Injected: value"); err == nil {
		t.Error("expected an error for a header name containing CRLF, got nil")
	}
}
