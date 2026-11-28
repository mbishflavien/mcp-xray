package inspector

import (
	"fmt"
	"net/url"
	"strings"
)

// ParseHeaderFlag parses a "Name: value" string into a header name and
// value, rejecting shapes that could not possibly be a valid HTTP header
// field before any connection is attempted.
func ParseHeaderFlag(raw string) (name, value string, err error) {
	rawName, rawValue, ok := strings.Cut(raw, ":")
	if !ok {
		return "", "", fmt.Errorf("header %q: missing ':' separator", raw)
	}
	name = strings.TrimSpace(rawName)
	value = strings.TrimSpace(rawValue)
	if name == "" {
		return "", "", fmt.Errorf("header %q: empty name", raw)
	}
	if strings.ContainsAny(name, "\r\n") || strings.ContainsAny(value, "\r\n") {
		return "", "", fmt.Errorf("header %q: name or value contains a CR or LF byte", raw)
	}
	return name, value, nil
}

// validateHTTPEndpoint checks that endpoint parses as a URL with an http
// or https scheme, before anything tries to connect to it.
func validateHTTPEndpoint(endpoint string) (*url.URL, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("unsupported scheme %q (must be http or https)", parsed.Scheme)
	}
	return parsed, nil
}
