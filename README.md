# mcp-xray

A security and compliance inspector for [MCP](https://modelcontextprotocol.io) servers.

Point it at an MCP server over stdio and it:

- Introspects every tool, resource, and prompt the server advertises.
- Generates adversarial payloads from each tool's input schema (type
  confusion, oversized strings, path traversal, null bytes, SQL/shell/template
  injection strings, mass assignment, missing required fields), actually
  calls the tool with each one, and classifies the real result.
- Gates every call through a destructive-tool-name safety policy first, so a
  probe can't actually invoke something like `delete_all_records` without an
  explicit `--allow-tool` opt-in.
- Scores the outcome by severity and reports it as text, JSON, or SARIF
  (`--format`), with `--fail-on <severity>` for CI gating.

Still missing, planned next: auth-bypass checks, rate-limit probing,
prompt-injection-in-output detection, an HTTP/Streamable transport (stdio
only for now), and a live terminal dashboard.

## Status

The schema-fuzz probe closes the full loop end to end: generate mutations,
call the real tool, classify the outcome (a healthy rejection, a silently
accepted invalid input, an internal error, a hang, or a crash), and emit a
scored Finding. Verified against a real MCP server (`cmd/example-server`),
including a mutation that genuinely crashes the target process and one that
genuinely hangs past the per-call timeout.

Known limitation: if one mutation crashes a tool, mcp-xray doesn't reconnect.
The scan stops retrying further mutations against *that* tool once it
crashes, but the next tool's first call can still surface one "crash"
finding of its own - that's fallout from the connection already being dead,
not an independently discovered bug in that tool. Treat the *first* crash
finding in a report as the real one. (Tools are listed alphabetically
regardless of registration order, so in `example-server`, `process`'s
crash always lands before `slow_echo` is probed - confirmed by disabling
`process`'s panic and re-running, which shows `slow_echo` genuinely timing
out on its own.)

Still missing: auth-bypass, rate-limit, and prompt-injection-in-output
probes; the live terminal dashboard; an HTTP/Streamable transport; and
caching the compiled WASI module across probe runs (every sandboxed call
currently recompiles it, which is correct but slow).

## Getting started

```bash
./scripts/build-probes.sh                       # compile WASI probes to internal/probes/bin/*.wasm
go build -o bin/mcp-xray ./cmd/mcp-xray
go build -o bin/example-server ./cmd/example-server   # a minimal MCP server to try it on

./bin/mcp-xray -- ./bin/example-server
./bin/mcp-xray --format sarif --fail-on high -- ./bin/example-server
./bin/mcp-xray --allow-tool delete_all_records -- ./bin/example-server
```

Requires Go 1.23 or newer.

## Architecture

Written in Go, using the official
[go-sdk](https://github.com/modelcontextprotocol/go-sdk) MCP client. Probes
that generate payloads run sandboxed as WASI modules via
[wazero](https://github.com/tetratelabs/wazero): no filesystem, network, or
environment access, just stdin/stdout, so a malicious or compromised target
can't use a probe to reach the host. The live dashboard will be a terminal UI
built with [Bubble Tea](https://github.com/charmbracelet/bubbletea) rather
than a web frontend.

The public packages (`findings`, `probe`, `scan`, `report`, `builtinprobes`)
are deliberately kept outside `internal/`: Go's `internal/` import rule means
anything under `internal/...` can only ever be imported from within this
module, so a type an out-of-tree package needs to reference has to live
outside it from the start.

```
cmd/
  mcp-xray/          CLI entry point: flags -> scan.Runner -> report.Writer
  example-server/    minimal real MCP server, used to smoke-test the pipeline
  probes/            WASI probe sources (compiled by scripts/build-probes.sh)

findings/            public: Finding, Severity
probe/               public: ToolCaller, Snapshot, Probe/ToolProbe/ServerProbe,
                     SafetyPolicy, BlockedError, Outcome + Classify()
scan/                public: Runner, the composition root that gates every
                     call through a SafetyPolicy and aggregates Findings
report/              public: Result, Writer (Text/JSON/SARIF), ExitCode()
builtinprobes/       public: constructs mcp-xray's own probes as probe.Probe
                     values, the one bridge from internal/ to the public API

internal/
  inspector/         MCP client wrapper: connect, introspect, CallTool
  safety/            KeywordPolicy, the default destructive-tool-name gate
  probeproto/        JSON wire types shared between the host and sandboxed probes
  probes/            embeds compiled probe .wasm, runs it through the sandbox,
                     and adapts it into a probe.ToolProbe
  probes/schemafuzz/ the schema-fuzz mutation generator (plain Go, natively testable)
  sandbox/           runs a probe's .wasm as a sandboxed WASI module via wazero
```
