package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// captureStdout temporarily redirects os.Stdout (run() writes its report
// there directly, not to an injectable io.Writer) and returns a function
// that restores it and returns everything written.
func captureStdout(t *testing.T) func() string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe() error: %v", err)
	}
	os.Stdout = w

	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		io.Copy(&buf, r)
		done <- buf.String()
	}()

	return func() string {
		w.Close()
		os.Stdout = old
		return <-done
	}
}

func TestRunRequiresEitherURLOrCommand(t *testing.T) {
	_, err := run([]string{"--"})
	if err == nil {
		t.Fatal("run() with neither -url nor a command: want an error, got nil")
	}
	if !strings.Contains(err.Error(), "no server command") {
		t.Errorf("error = %q, want it to mention a missing server command", err)
	}
}

func TestRunRejectsURLAndCommandTogether(t *testing.T) {
	_, err := run([]string{"-url", "http://localhost:1", "--", "echo", "hi"})
	if err == nil {
		t.Fatal("run() with both -url and a command: want an error, got nil")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("error = %q, want it to mention they're mutually exclusive", err)
	}
}

func TestRunRejectsMissingDoubleDash(t *testing.T) {
	_, err := run([]string{"-url", "http://localhost:1"})
	if err == nil {
		t.Fatal("run() with no -- at all: want an error, got nil")
	}
}

func TestRunRejectsHeaderWithoutURL(t *testing.T) {
	_, err := run([]string{"-header", "Authorization: Bearer x", "--", "echo", "hi"})
	if err == nil {
		t.Fatal("run() with -header but no -url: want an error, got nil")
	}
	if !strings.Contains(err.Error(), "-header") {
		t.Errorf("error = %q, want it to mention -header", err)
	}
}

func TestRunRejectsMalformedHeaderBeforeConnecting(t *testing.T) {
	_, err := run([]string{"-url", "http://localhost:1", "-header", "no-colon", "--"})
	if err == nil {
		t.Fatal("run() with a malformed -header value: want an error, got nil")
	}
	if !strings.Contains(err.Error(), "':'") {
		t.Errorf("error = %q, want it to mention the missing ':' separator", err)
	}
}

func TestRunRejectsInsecureSkipTLSVerifyWithoutURL(t *testing.T) {
	_, err := run([]string{"-insecure-skip-tls-verify", "--", "echo", "hi"})
	if err == nil {
		t.Fatal("run() with -insecure-skip-tls-verify but no -url: want an error, got nil")
	}
	if !strings.Contains(err.Error(), "-insecure-skip-tls-verify") {
		t.Errorf("error = %q, want it to mention -insecure-skip-tls-verify", err)
	}
}

// TestRunRejectsBadURLScheme confirms a -url with an unsupported scheme
// fails before run() ever tries to connect, surfacing
// inspector.ConnectHTTP's own validation through the CLI.
func TestRunRejectsBadURLScheme(t *testing.T) {
	_, err := run([]string{"-url", "ftp://example.com", "--"})
	if err == nil {
		t.Fatal("run() with a non-HTTP -url scheme: want an error, got nil")
	}
	if !strings.Contains(err.Error(), "scheme") {
		t.Errorf("error = %q, want it to mention the unsupported scheme", err)
	}
}

type e2eGreetArgs struct {
	Name string `json:"name" jsonschema:"the person to greet"`
}

// TestRunConnectsOverHTTP runs the full run() path end to end against a
// real MCP server reached over HTTP via -url, the same dispatch the
// manual example-server -http verification already confirmed by hand -
// this locks it in as a permanent regression test.
func TestRunConnectsOverHTTP(t *testing.T) {
	mcpServer := mcp.NewServer(&mcp.Implementation{Name: "e2e-test-server", Version: "1.0.0"}, nil)
	mcp.AddTool(mcpServer, &mcp.Tool{Name: "greet", Description: "say hi"},
		func(_ context.Context, _ *mcp.CallToolRequest, args e2eGreetArgs) (*mcp.CallToolResult, any, error) {
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "Hi " + args.Name}}}, nil, nil
		})
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return mcpServer }, nil)
	srv := httptest.NewServer(handler)
	defer srv.Close()

	restore := captureStdout(t)
	code, err := run([]string{"-timeout", "5s", "-url", srv.URL, "--"})
	output := restore()

	if err != nil {
		t.Fatalf("run() error: %v", err)
	}
	if code != 0 {
		t.Errorf("run() exit code = %d, want 0", code)
	}
	if !strings.Contains(output, "e2e-test-server") {
		t.Errorf("output = %q, want it to mention the server name", output)
	}
}
