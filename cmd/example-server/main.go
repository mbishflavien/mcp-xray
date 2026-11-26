// Command example-server is a minimal MCP server over stdio, used to
// smoke-test mcp-xray against a real process without depending on any
// third-party server package.
package main

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type greetArgs struct {
	Name string `json:"name" jsonschema:"the person to greet"`
}

type processArgs struct {
	Data string `json:"data" jsonschema:"data to process"`
}

type slowEchoArgs struct {
	Text string `json:"text" jsonschema:"text to echo back slowly"`
}

type deleteAllRecordsArgs struct {
	Table string `json:"table" jsonschema:"the table to delete every record from"`
}

type getAccountArgs struct {
	AccountID string `json:"account_id" jsonschema:"the account to fetch"`
	Role      string `json:"role" jsonschema:"the caller's role"`
}

func main() {
	server := mcp.NewServer(&mcp.Implementation{Name: "example-server", Version: "0.1.0"}, nil)

	mcp.AddTool(server, &mcp.Tool{Name: "greet", Description: "say hi to someone"},
		func(_ context.Context, _ *mcp.CallToolRequest, args greetArgs) (*mcp.CallToolResult, any, error) {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: "Hi " + args.Name}},
			}, nil, nil
		})

	// slow_echo deliberately hangs well past any reasonable per-call
	// timeout, so mcp-xray's timeout handling has something real to
	// catch end to end.
	mcp.AddTool(server, &mcp.Tool{Name: "slow_echo", Description: "echo text back, slowly"},
		func(ctx context.Context, _ *mcp.CallToolRequest, args slowEchoArgs) (*mcp.CallToolResult, any, error) {
			select {
			case <-time.After(30 * time.Second):
			case <-ctx.Done():
			}
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: args.Text}},
			}, nil, nil
		})

	// get_account is deliberately vulnerable: it returns account data for
	// whatever account_id is given and honors whatever role is claimed,
	// with no real check at all - a broken object/function-level
	// authorization bug, exactly what the auth-bypass probe exists to
	// catch.
	mcp.AddTool(server, &mcp.Tool{Name: "get_account", Description: "fetch an account's balance"},
		func(_ context.Context, _ *mcp.CallToolRequest, args getAccountArgs) (*mcp.CallToolResult, any, error) {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{
					Text: fmt.Sprintf("account %s (role=%s): balance $100,000", args.AccountID, args.Role),
				}},
			}, nil, nil
		})

	// delete_all_records does nothing destructive at all; its name
	// alone is what exists to exercise safety.KeywordPolicy blocking it
	// by default.
	mcp.AddTool(server, &mcp.Tool{Name: "delete_all_records", Description: "delete every record"},
		func(_ context.Context, _ *mcp.CallToolRequest, _ deleteAllRecordsArgs) (*mcp.CallToolResult, any, error) {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: "deleted"}},
			}, nil, nil
		})

	// process is deliberately broken: a null byte in its input crashes
	// the whole server process. Registered last so its crash doesn't
	// poison any tool after it - delete_all_records is unaffected
	// either way, since the safety gate blocks it before a real call is
	// ever attempted, dead connection or not.
	mcp.AddTool(server, &mcp.Tool{Name: "process", Description: "process some data"},
		func(_ context.Context, _ *mcp.CallToolRequest, args processArgs) (*mcp.CallToolResult, any, error) {
			if strings.Contains(args.Data, "\x00") {
				panic("process: null byte in data")
			}
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: "processed: " + args.Data}},
			}, nil, nil
		})

	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}
