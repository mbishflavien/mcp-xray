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

Early scaffold. The core introspection + probe engine is being built first;
a live terminal dashboard and Postman-collection export come later.

## Getting started

```bash
go build -o bin/mcp-xray ./cmd/mcp-xray
./bin/mcp-xray -- <command to start the MCP server>
```

Requires Go 1.23 or newer.

## Architecture

Written in Go, using the official
[go-sdk](https://github.com/modelcontextprotocol/go-sdk) MCP client. The live
dashboard is a terminal UI built with [Bubble Tea](https://github.com/charmbracelet/bubbletea)
rather than a web frontend.

```
cmd/mcp-xray/      CLI entry point
internal/
  findings/        shared types: Finding, Severity
  inspector/        MCP client wrapper: connect, introspect tools/resources/prompts
  probes/          security probe implementations
  report/          scoring and report output
  tui/             Bubble Tea live dashboard
```
