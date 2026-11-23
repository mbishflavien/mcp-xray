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
