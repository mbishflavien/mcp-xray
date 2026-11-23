// Command mcp-xray connects to an MCP server, introspects it, and runs
// security probes against what it finds.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"

	"github.com/mbishflavien/mcp-xray/internal/inspector"
	"github.com/mbishflavien/mcp-xray/internal/probes"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "mcp-xray:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: mcp-xray -- <command to start the MCP server> [args...]")
	}
	if args[0] == "--" {
		args = args[1:]
	}
	if len(args) == 0 {
		return fmt.Errorf("no server command given after --")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	session, err := inspector.ConnectCommand(ctx, args[0], args[1:]...)
	if err != nil {
		return err
	}
	defer session.Close()

	snap, err := session.Snapshot(ctx)
	if err != nil {
		return fmt.Errorf("introspect server: %w", err)
	}

	fmt.Printf("%s %s\n", snap.ServerName, snap.ServerVersion)
	fmt.Printf("%d tools, %d resources, %d prompts\n\n", len(snap.Tools), len(snap.Resources), len(snap.Prompts))

	for _, tool := range snap.Tools {
		fmt.Printf("tool %q: %s\n", tool.Name, tool.Description)

		schema, err := json.Marshal(tool.InputSchema)
		if err != nil {
			fmt.Printf("  schema fuzz skipped: marshal input schema: %v\n", err)
			continue
		}

		mutations, err := probes.SchemaFuzzMutations(ctx, tool.Name, schema)
		if err != nil {
			fmt.Printf("  schema fuzz skipped: %v\n", err)
			continue
		}
		for _, m := range mutations {
			fmt.Printf("  [%s] %s\n", m.Kind, m.Description)
		}
	}

	return nil
}
