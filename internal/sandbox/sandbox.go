// Package sandbox runs probes as WASI modules via wazero: no filesystem, no
// network, no clock access beyond what WASI requires to start — just
// stdin/stdout, a bounded amount of memory, and a hard execution deadline.
// A malicious or compromised MCP server can feed adversarial data into a
// probe (for example, a pathological JSON schema) without that probe being
// able to touch the host, exhaust its memory, or hang it forever.
package sandbox

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

// DefaultTimeout is a sensible default for Run's timeout parameter: generous
// for a probe doing in-memory parsing/generation, short enough that a
// malicious input can't hang the scan indefinitely.
const DefaultTimeout = 10 * time.Second

// memoryLimitPages caps a probe's WASI linear memory at 16MiB (16MiB /
// 64KiB-per-page). wazero's default is 4GB; a probe generating payloads
// from an adversarial schema has no legitimate reason to need anywhere
// near that.
const memoryLimitPages = 256

// Run instantiates the given WASI module, feeds it input on stdin, and
// returns whatever it wrote to stdout. Each call gets a fresh runtime, so
// probes cannot share state between runs. If the module hasn't finished
// within timeout, it is forcibly closed and Run returns an error instead
// of blocking forever.
func Run(ctx context.Context, wasmBinary []byte, input []byte, timeout time.Duration) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	runtimeConfig := wazero.NewRuntimeConfig().
		// Without this, a probe stuck in a tight loop (buggy, or crafted
		// from an adversarial input) can block its goroutine, and
		// potentially its OS thread, forever: ctx cancellation is
		// otherwise cooperative, not preemptive. See wazero's own doc on
		// WithCloseOnContextDone for why this matters for untrusted Wasm.
		WithCloseOnContextDone(true).
		WithMemoryLimitPages(memoryLimitPages)
	runtime := wazero.NewRuntimeWithConfig(ctx, runtimeConfig)
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
