// Package inspector connects to an MCP server over stdio and introspects
// everything it advertises: tools, resources, and prompts.
package inspector

import (
	"context"
	"fmt"
	"os/exec"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Session wraps a live connection to one MCP server.
type Session struct {
	session *mcp.ClientSession
}

// Connect opens a client session over the given transport. Tests use this
// directly with an in-memory transport; ConnectCommand is the real-world
// entry point.
func Connect(ctx context.Context, transport mcp.Transport) (*Session, error) {
	client := mcp.NewClient(&mcp.Implementation{Name: "mcp-xray", Version: "0.1.0"}, nil)

	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	return &Session{session: session}, nil
}

// ConnectCommand starts the given command and connects to it as an MCP
// server over stdio.
func ConnectCommand(ctx context.Context, command string, args ...string) (*Session, error) {
	s, err := Connect(ctx, &mcp.CommandTransport{Command: exec.Command(command, args...)})
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", command, err)
	}
	return s, nil
}

// Close ends the connection, terminating the server process if it was
// started by ConnectCommand.
func (s *Session) Close() error {
	return s.session.Close()
}

// CapabilitySnapshot is everything a server advertised at connect time.
type CapabilitySnapshot struct {
	ServerName    string
	ServerVersion string
	Tools         []*mcp.Tool
	Resources     []*mcp.Resource
	Prompts       []*mcp.Prompt
}

// Snapshot introspects the connected server's tools, resources, and
// prompts.
func (s *Session) Snapshot(ctx context.Context) (*CapabilitySnapshot, error) {
	snap := &CapabilitySnapshot{}

	if init := s.session.InitializeResult(); init != nil && init.ServerInfo != nil {
		snap.ServerName = init.ServerInfo.Name
		snap.ServerVersion = init.ServerInfo.Version
	}

	for tool, err := range s.session.Tools(ctx, nil) {
		if err != nil {
			return nil, fmt.Errorf("list tools: %w", err)
		}
		snap.Tools = append(snap.Tools, tool)
	}

	for resource, err := range s.session.Resources(ctx, nil) {
		if err != nil {
			return nil, fmt.Errorf("list resources: %w", err)
		}
		snap.Resources = append(snap.Resources, resource)
	}

	for prompt, err := range s.session.Prompts(ctx, nil) {
		if err != nil {
			return nil, fmt.Errorf("list prompts: %w", err)
		}
		snap.Prompts = append(snap.Prompts, prompt)
	}

	return snap, nil
}
