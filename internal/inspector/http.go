package inspector

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

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
// MCP Streamable HTTP transport. timeout bounds dialing, the TLS
// handshake, and waiting for response headers on every request the
// resulting session makes - deliberately explicit rather than left to
// net/http's unbounded defaults, since a malicious or compromised target
// could otherwise hang any of those stages indefinitely. It does not
// bound how long a call's body takes to finish sending or being read;
// callers already bound that themselves via ctx, exactly as
// ConnectCommand's callers do today.
func ConnectHTTP(ctx context.Context, endpoint string, timeout time.Duration, cfg HTTPConfig) (*Session, error) {
	if _, err := validateHTTPEndpoint(endpoint); err != nil {
		return nil, fmt.Errorf("connect to %s: %w", endpoint, err)
	}

	dialer := &net.Dialer{Timeout: timeout}
	client := &http.Client{
		Transport: &headerInjectingTransport{
			base: &http.Transport{
				DialContext:           dialer.DialContext,
				TLSHandshakeTimeout:   timeout,
				ResponseHeaderTimeout: timeout,
			},
			headers: cfg.Headers,
		},
	}

	s, err := Connect(ctx, &mcp.StreamableClientTransport{Endpoint: endpoint, HTTPClient: client})
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", endpoint, err)
	}
	return s, nil
}

// refuseRedirects always refuses to follow a redirect. The server being
// scanned could otherwise redirect a request elsewhere - possibly to a
// host that shouldn't receive whatever headers headerInjectingTransport
// attaches to every request (a bearer token, say) - so mcp-xray never
// follows one silently: it fails the connection with a clear error
// instead.
func refuseRedirects(req *http.Request, _ []*http.Request) error {
	return fmt.Errorf("refusing to follow redirect to %s", req.URL)
}

// headerInjectingTransport wraps a base http.RoundTripper to attach
// configured headers (for example, Authorization) to every outgoing
// request. A server being scanned never sees a header it wasn't given.
type headerInjectingTransport struct {
	base    http.RoundTripper
	headers map[string]string
}

func (t *headerInjectingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if len(t.headers) > 0 {
		req = req.Clone(req.Context())
		for name, value := range t.headers {
			req.Header.Set(name, value)
		}
	}
	return t.base.RoundTrip(req)
}
