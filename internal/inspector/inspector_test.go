package inspector

import (
	"context"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type greetArgs struct {
	Name string `json:"name" jsonschema:"the person to greet"`
}

func startTestServer(ctx context.Context, t *testing.T) *Session {
	t.Helper()

	server := mcp.NewServer(&mcp.Implementation{Name: "test-server", Version: "1.2.3"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "greet", Description: "say hi"},
		func(_ context.Context, _ *mcp.CallToolRequest, args greetArgs) (*mcp.CallToolResult, any, error) {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: "Hi " + args.Name}},
			}, nil, nil
		})
	server.AddResource(&mcp.Resource{URI: "file:///readme.txt", Name: "readme"}, nil)
	server.AddPrompt(&mcp.Prompt{Name: "welcome"}, nil)

	clientTransport, serverTransport := mcp.NewInMemoryTransports()

	if _, err := server.Connect(ctx, serverTransport, nil); err != nil {
		t.Fatalf("server.Connect() error: %v", err)
	}

	session, err := Connect(ctx, clientTransport)
	if err != nil {
		t.Fatalf("Connect() error: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session
}

// TestSnapshotCapsToolCount confirms Snapshot doesn't collect an
// unbounded number of tools from a server. The SDK's own pagination has
// no cap on page count, so a malicious or buggy server returning many
// more tools than any real one would is exactly the scenario maxListItems
// exists to bound.
func TestSnapshotCapsToolCount(t *testing.T) {
	old := maxListItems
	maxListItems = 3
	t.Cleanup(func() { maxListItems = old })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	server := mcp.NewServer(&mcp.Implementation{Name: "many-tools-server", Version: "1.0.0"}, nil)
	for i := range 10 {
		name := "tool_" + string(rune('a'+i))
		mcp.AddTool(server, &mcp.Tool{Name: name, Description: "a tool"},
			func(_ context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
				return &mcp.CallToolResult{}, nil, nil
			})
	}

	clientTransport, serverTransport := mcp.NewInMemoryTransports()
	if _, err := server.Connect(ctx, serverTransport, nil); err != nil {
		t.Fatalf("server.Connect() error: %v", err)
	}
	session, err := Connect(ctx, clientTransport)
	if err != nil {
		t.Fatalf("Connect() error: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })

	snap, err := session.Snapshot(ctx)
	if err != nil {
		t.Fatalf("Snapshot() error: %v", err)
	}
	if len(snap.Tools) != 3 {
		t.Errorf("Snapshot() collected %d tools from a 10-tool server with maxListItems=3, want exactly 3", len(snap.Tools))
	}
}

func TestSnapshot(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	session := startTestServer(ctx, t)

	snap, err := session.Snapshot(ctx)
	if err != nil {
		t.Fatalf("Snapshot() error: %v", err)
	}

	if snap.ServerName != "test-server" || snap.ServerVersion != "1.2.3" {
		t.Errorf("server info = %q %q, want %q %q", snap.ServerName, snap.ServerVersion, "test-server", "1.2.3")
	}
	if len(snap.Tools) != 1 || snap.Tools[0].Name != "greet" {
		t.Errorf("tools = %v, want one tool named greet", snap.Tools)
	}
	if len(snap.Resources) != 1 || snap.Resources[0].URI != "file:///readme.txt" {
		t.Errorf("resources = %v, want one resource file:///readme.txt", snap.Resources)
	}
	if len(snap.Prompts) != 1 || snap.Prompts[0].Name != "welcome" {
		t.Errorf("prompts = %v, want one prompt named welcome", snap.Prompts)
	}
}

func TestCallTool(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	session := startTestServer(ctx, t)

	result, err := session.CallTool(ctx, "greet", map[string]any{"name": "Flavien"})
	if err != nil {
		t.Fatalf("CallTool() error: %v", err)
	}
	if len(result.Content) != 1 {
		t.Fatalf("result.Content = %v, want one item", result.Content)
	}
	text, ok := result.Content[0].(*mcp.TextContent)
	if !ok || text.Text != "Hi Flavien" {
		t.Errorf("result.Content[0] = %v, want text %q", result.Content[0], "Hi Flavien")
	}
}

func TestCallToolUnknownTool(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	session := startTestServer(ctx, t)

	if _, err := session.CallTool(ctx, "does-not-exist", nil); err == nil {
		t.Error("CallTool() with an unknown tool name: want an error, got nil")
	}
}
