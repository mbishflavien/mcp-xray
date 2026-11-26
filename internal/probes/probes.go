// Package probes exposes the compiled WASI probes bundled into the
// mcp-xray binary, running each one through the sandbox.
package probes

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/mbishflavien/mcp-xray/internal/probeproto"
	"github.com/mbishflavien/mcp-xray/internal/sandbox"
)

//go:embed bin/schemafuzz.wasm
var schemaFuzzWasm []byte

//go:embed bin/authbypass.wasm
var authBypassWasm []byte

// SchemaFuzzMutations runs the schema-fuzz probe sandboxed and returns the
// adversarial payloads it generated for the given tool.
func SchemaFuzzMutations(ctx context.Context, toolName string, schema json.RawMessage) ([]probeproto.Mutation, error) {
	return runMutationProbe(ctx, schemaFuzzWasm, toolName, schema)
}

// AuthBypassMutations runs the auth-bypass probe sandboxed and returns the
// forged identity/privilege/credential payloads it generated for the given
// tool.
func AuthBypassMutations(ctx context.Context, toolName string, schema json.RawMessage) ([]probeproto.Mutation, error) {
	return runMutationProbe(ctx, authBypassWasm, toolName, schema)
}

// runMutationProbe sends a MutationRequest to a sandboxed WASI probe and
// parses its MutationResponse. Both schema-fuzz and auth-bypass share this
// exact request/response shape: a tool name and schema in, mutations (or an
// error message) out.
func runMutationProbe(ctx context.Context, wasm []byte, toolName string, schema json.RawMessage) ([]probeproto.Mutation, error) {
	input, err := json.Marshal(probeproto.MutationRequest{ToolName: toolName, Schema: schema})
	if err != nil {
		return nil, fmt.Errorf("marshal probe input: %w", err)
	}

	out, err := sandbox.Run(ctx, wasm, input, sandbox.DefaultTimeout)
	if err != nil {
		return nil, err
	}

	var output probeproto.MutationResponse
	if err := json.Unmarshal(out, &output); err != nil {
		return nil, fmt.Errorf("parse probe output: %w", err)
	}
	if output.Error != "" {
		return nil, errors.New(output.Error)
	}
	return output.Mutations, nil
}
