package inspector

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// fakeRoundTripper records the request it received and returns a fixed,
// empty-body response, so headerInjectingTransport's own logic can be
// tested directly without a real network call.
type fakeRoundTripper struct {
	gotHeaders http.Header
}

func (f *fakeRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	f.gotHeaders = req.Header
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(""))}, nil
}

// startTestHTTPServer serves a tiny real MCP server (one "greet" tool,
// the same shape as inspector_test.go's startTestServer) over the MCP
// Streamable HTTP transport, on a local httptest.Server. The caller's
// t.Cleanup closes it.
func startTestHTTPServer(t *testing.T) *httptest.Server {
	t.Helper()

	mcpServer := mcp.NewServer(&mcp.Implementation{Name: "http-test-server", Version: "1.0.0"}, nil)
	mcp.AddTool(mcpServer, &mcp.Tool{Name: "greet", Description: "say hi"},
		func(_ context.Context, _ *mcp.CallToolRequest, args greetArgs) (*mcp.CallToolResult, any, error) {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: "Hi " + args.Name}},
			}, nil, nil
		})

	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return mcpServer }, nil)
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv
}

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

func TestValidateHTTPEndpoint(t *testing.T) {
	if _, err := validateHTTPEndpoint("https://example.com/mcp"); err != nil {
		t.Errorf("validateHTTPEndpoint() error: %v", err)
	}
	if _, err := validateHTTPEndpoint("http://localhost:8080"); err != nil {
		t.Errorf("validateHTTPEndpoint() error: %v", err)
	}
}

func TestValidateHTTPEndpointRejectsBadScheme(t *testing.T) {
	for _, endpoint := range []string{"ftp://example.com", "file:///etc/passwd", "ws://example.com"} {
		if _, err := validateHTTPEndpoint(endpoint); err == nil {
			t.Errorf("validateHTTPEndpoint(%q): want an error, got nil", endpoint)
		}
	}
}

func TestValidateHTTPEndpointRejectsMalformedURL(t *testing.T) {
	if _, err := validateHTTPEndpoint("http://exa mple.com"); err == nil {
		t.Error("validateHTTPEndpoint() with a malformed URL: want an error, got nil")
	}
}

func TestConnectHTTP(t *testing.T) {
	srv := startTestHTTPServer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	session, err := ConnectHTTP(ctx, srv.URL, 5*time.Second, HTTPConfig{})
	if err != nil {
		t.Fatalf("ConnectHTTP() error: %v", err)
	}
	defer session.Close()

	snap, err := session.Snapshot(ctx)
	if err != nil {
		t.Fatalf("Snapshot() error: %v", err)
	}
	if len(snap.Tools) != 1 || snap.Tools[0].Name != "greet" {
		t.Errorf("tools = %v, want one tool named greet", snap.Tools)
	}

	result, err := session.CallTool(ctx, "greet", map[string]any{"name": "Flavien"})
	if err != nil {
		t.Fatalf("CallTool() error: %v", err)
	}
	text, ok := result.Content[0].(*mcp.TextContent)
	if !ok || text.Text != "Hi Flavien" {
		t.Errorf("result.Content[0] = %v, want text %q", result.Content[0], "Hi Flavien")
	}
}

func TestConnectHTTPRejectsBadScheme(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if _, err := ConnectHTTP(ctx, "ftp://example.com", 5*time.Second, HTTPConfig{}); err == nil {
		t.Error("ConnectHTTP() with a non-HTTP scheme: want an error, got nil")
	}
}

// TestConnectHTTPResponseHeaderTimeout confirms a server that accepts the
// connection but never sends response headers is bounded by timeout, not
// left to hang for the lifetime of a much longer (or absent) context
// deadline.
func TestConnectHTTPResponseHeaderTimeout(t *testing.T) {
	hang := make(chan struct{})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-hang
	}))
	// srv.Close blocks until every outstanding handler returns, so hang
	// must close BEFORE srv.Close runs - t.Cleanup runs LIFO, so srv.Close
	// is registered first (runs last) and closing hang is registered
	// second (runs first).
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(hang) })

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	start := time.Now()
	_, err := ConnectHTTP(ctx, srv.URL, 500*time.Millisecond, HTTPConfig{})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("ConnectHTTP() against a server that never responds: want an error, got nil")
	}
	if elapsed > 10*time.Second {
		t.Errorf("ConnectHTTP() took %v with a 500ms timeout; the 30s context deadline should never be the thing that fired", elapsed)
	}
}

// TestHeaderInjectingTransportSetsConfiguredHeaders confirms the
// transport attaches every configured header to the request before
// delegating to its base RoundTripper.
func TestHeaderInjectingTransportSetsConfiguredHeaders(t *testing.T) {
	base := &fakeRoundTripper{}
	rt := &headerInjectingTransport{base: base, headers: map[string]string{"Authorization": "Bearer x", "X-Custom": "y"}}

	req, err := http.NewRequest(http.MethodGet, "http://example.com", nil)
	if err != nil {
		t.Fatalf("http.NewRequest() error: %v", err)
	}
	if _, err := rt.RoundTrip(req); err != nil {
		t.Fatalf("RoundTrip() error: %v", err)
	}

	if got := base.gotHeaders.Get("Authorization"); got != "Bearer x" {
		t.Errorf("Authorization = %q, want %q", got, "Bearer x")
	}
	if got := base.gotHeaders.Get("X-Custom"); got != "y" {
		t.Errorf("X-Custom = %q, want %q", got, "y")
	}
}

// TestHeaderInjectingTransportNoHeadersConfigured confirms a nil/empty
// header map doesn't touch the request at all.
func TestHeaderInjectingTransportNoHeadersConfigured(t *testing.T) {
	base := &fakeRoundTripper{}
	rt := &headerInjectingTransport{base: base}

	req, err := http.NewRequest(http.MethodGet, "http://example.com", nil)
	if err != nil {
		t.Fatalf("http.NewRequest() error: %v", err)
	}
	if _, err := rt.RoundTrip(req); err != nil {
		t.Fatalf("RoundTrip() error: %v", err)
	}
	if len(base.gotHeaders) != 0 {
		t.Errorf("gotHeaders = %v, want no headers set", base.gotHeaders)
	}
}

// TestConnectHTTPSendsConfiguredHeaders confirms a header configured via
// HTTPConfig actually reaches a real server on every request, not just
// the first one.
func TestConnectHTTPSendsConfiguredHeaders(t *testing.T) {
	var gotAuth string
	mcpServer := mcp.NewServer(&mcp.Implementation{Name: "http-test-server", Version: "1.0.0"}, nil)
	mcp.AddTool(mcpServer, &mcp.Tool{Name: "whoami", Description: "report the Authorization header seen"},
		func(_ context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: gotAuth}}}, nil, nil
		})
	handler := mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
		gotAuth = r.Header.Get("Authorization")
		return mcpServer
	}, nil)
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	session, err := ConnectHTTP(ctx, srv.URL, 5*time.Second, HTTPConfig{
		Headers: map[string]string{"Authorization": "Bearer test-token"},
	})
	if err != nil {
		t.Fatalf("ConnectHTTP() error: %v", err)
	}
	defer session.Close()

	if gotAuth != "Bearer test-token" {
		t.Errorf("server saw Authorization = %q, want %q", gotAuth, "Bearer test-token")
	}

	if _, err := session.CallTool(ctx, "whoami", nil); err != nil {
		t.Fatalf("CallTool() error: %v", err)
	}
	if gotAuth != "Bearer test-token" {
		t.Errorf("server saw Authorization = %q on CallTool, want %q", gotAuth, "Bearer test-token")
	}
}

// TestConnectHTTPMultipleHeaders confirms several configured headers all
// reach the server, and a repeated header name takes the last value
// given - the same "last one wins" rule map assignment already gives
// ConnectHTTP's caller for free, so this just documents and locks in
// that behavior.
func TestConnectHTTPMultipleHeaders(t *testing.T) {
	var gotAuth, gotCustom string
	mcpServer := mcp.NewServer(&mcp.Implementation{Name: "http-test-server", Version: "1.0.0"}, nil)
	handler := mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
		gotAuth = r.Header.Get("Authorization")
		gotCustom = r.Header.Get("X-Custom")
		return mcpServer
	}, nil)
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	session, err := ConnectHTTP(ctx, srv.URL, 5*time.Second, HTTPConfig{
		Headers: map[string]string{
			"Authorization": "Bearer second-wins",
			"X-Custom":      "value",
		},
	})
	if err != nil {
		t.Fatalf("ConnectHTTP() error: %v", err)
	}
	defer session.Close()

	if gotAuth != "Bearer second-wins" || gotCustom != "value" {
		t.Errorf("server saw Authorization=%q X-Custom=%q, want %q and %q", gotAuth, gotCustom, "Bearer second-wins", "value")
	}
}
