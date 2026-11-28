package inspector

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// HTTPConfig configures ConnectHTTP's connection to a remote MCP server.
type HTTPConfig struct {
	// Headers are sent with every request to the server (for example,
	// Authorization). Keys and values must not contain CR or LF bytes;
	// build this map from repeated "Name: value" flags with
	// ParseHeaderFlag.
	Headers map[string]string
}

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

// ConnectHTTP connects to an MCP server reachable over HTTP, using the
// MCP Streamable HTTP transport.
func ConnectHTTP(ctx context.Context, endpoint string, cfg HTTPConfig) (*Session, error) {
	if _, err := validateHTTPEndpoint(endpoint); err != nil {
		return nil, fmt.Errorf("connect to %s: %w", endpoint, err)
	}

	client := &http.Client{}

	s, err := Connect(ctx, &mcp.StreamableClientTransport{Endpoint: endpoint, HTTPClient: client})
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", endpoint, err)
	}
	return s, nil
}
