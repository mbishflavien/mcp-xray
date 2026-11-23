// Package sandbox runs probes as WASI modules via wazero: no filesystem, no
// network, no clock access beyond what WASI requires to start — just
// stdin/stdout. A malicious or compromised MCP server can feed adversarial
// data into a probe without that probe being able to touch the host.
package sandbox

import (
	"bytes"
	"context"
	"fmt"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

// Run instantiates the given WASI module, feeds it input on stdin, and
// returns whatever it wrote to stdout. Each call gets a fresh runtime, so
// probes cannot share state between runs.
func Run(ctx context.Context, wasmBinary []byte, input []byte) ([]byte, error) {
	runtime := wazero.NewRuntime(ctx)
	defer runtime.Close(ctx)

	if _, err := wasi_snapshot_preview1.Instantiate(ctx, runtime); err != nil {
		return nil, fmt.Errorf("instantiate WASI: %w", err)
	}

	var stdout, stderr bytes.Buffer
	config := wazero.NewModuleConfig().
		WithStdin(bytes.NewReader(input)).
		WithStdout(&stdout).
		WithStderr(&stderr)
		// No WithFS, no WithEnv, no network import: the module has no
		// filesystem, environment, or network access.

	if _, err := runtime.InstantiateWithConfig(ctx, wasmBinary, config); err != nil {
		return nil, fmt.Errorf("run probe: %w (stderr: %s)", err, stderr.String())
	}
	return stdout.Bytes(), nil
}
