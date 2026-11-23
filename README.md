# mcp-xray

A security and compliance inspector for [MCP](https://modelcontextprotocol.io) servers.

Point it at any MCP server (stdio or HTTP) and it:

- Introspects every tool, resource, and prompt the server advertises.
- Runs a battery of security probes against each tool: schema-bypass fuzzing
  (type confusion, oversized payloads, path traversal, injection strings, null
  bytes), auth-bypass checks, rate-limit probing, and prompt-injection-in-output
  detection.
- Scores the server and reports findings by severity, with the evidence for
  each one.

## Status

Working end to end for the first probe: connect to a server, introspect its
tools, and generate schema-fuzz payloads for each one, sandboxed. Still
missing: actually calling the tool with each payload and turning the result
into a scored Finding, more probe types (auth-bypass, rate-limit,
prompt-injection-in-output), and the live terminal dashboard.

## Getting started

```bash
./scripts/build-probes.sh                       # compile WASI probes to internal/probes/bin/*.wasm
go build -o bin/mcp-xray ./cmd/mcp-xray
go build -o bin/example-server ./cmd/example-server   # a minimal MCP server to try it on

./bin/mcp-xray -- ./bin/example-server
```

Requires Go 1.23 or newer.

## Architecture

Written in Go, using the official
[go-sdk](https://github.com/modelcontextprotocol/go-sdk) MCP client. Probes
run sandboxed as WASI modules via [wazero](https://github.com/tetratelabs/wazero):
no filesystem, network, or environment access, just stdin/stdout, so a
malicious or compromised target can't use a probe to reach the host. The live
dashboard will be a terminal UI built with
[Bubble Tea](https://github.com/charmbracelet/bubbletea) rather than a web
frontend.

```
cmd/
  mcp-xray/          CLI entry point
  example-server/    minimal real MCP server, used to smoke-test the pipeline
  probes/            WASI probe sources (compiled by scripts/build-probes.sh)
internal/
  findings/          shared types: Finding, Severity
  inspector/         MCP client wrapper: connect, introspect tools/resources/prompts
  probeproto/        JSON wire types shared between the host and sandboxed probes
  probes/            embeds compiled probe .wasm, runs them through the sandbox
  probes/schemafuzz/ the schema-fuzz mutation generator (plain Go, natively testable)
  sandbox/           runs a probe's .wasm as a sandboxed WASI module via wazero
```
