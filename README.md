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
a live dashboard and Postman-collection export come later.

## Getting started

```bash
npm install
npm run dev -- <command to start the MCP server>
```

Requires Node.js 20 or newer.

## Architecture

```
src/
  types.ts        shared types: findings, severity, capability snapshot
  cli.ts          entry point
  mcp/            MCP client wrapper (connect, introspect)
  probes/         security probe implementations
  report/         scoring and report output
```
