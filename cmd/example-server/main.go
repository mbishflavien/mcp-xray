// Command example-server is a minimal MCP server over stdio, used to
// smoke-test mcp-xray against a real process without depending on any
// third-party server package.
package main

import (
	"context"
	"log"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type greetArgs struct {
	Name string `json:"name" jsonschema:"the person to greet"`
}

func main() {
	server := mcp.NewServer(&mcp.Implementation{Name: "example-server", Version: "0.1.0"}, nil)

	mcp.AddTool(server, &mcp.Tool{Name: "greet", Description: "say hi to someone"},
		func(_ context.Context, _ *mcp.CallToolRequest, args greetArgs) (*mcp.CallToolResult, any, error) {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: "Hi " + args.Name}},
			}, nil, nil
		})

	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}
