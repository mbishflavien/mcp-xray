# mcp-xray

A security and compliance inspector for [MCP](https://modelcontextprotocol.io) servers.

Point it at an MCP server over stdio and it:

- Introspects every tool, resource, and prompt the server advertises.
- Generates adversarial payloads from each tool's input schema (type
  confusion, oversized strings, path traversal, null bytes, SQL/shell/template
  injection strings, mass assignment, missing required fields), actually
  calls the tool with each one, and classifies the real result.
- Looks for broken object/function-level authorization: any field in a
  tool's schema shaped like an identity, a role, or a credential gets a
  forged value (someone else's id, `role: "admin"`, a blank token), and a
  silently-accepted bypass attempt is flagged High.
- Bursts every tool with the same benign, valid-looking arguments several
  times in a row: a tool that crashes or hangs under that repeated load is
  flagged High, and one that shows no sign of being rate-limited at all
  (no rejection, no growing latency) is flagged Low as a missing control.
- Gates every call through a destructive-tool-name safety policy first, so a
  probe can't actually invoke something like `delete_all_records` without an
  explicit `--allow-tool` opt-in.
- Scores the outcome by severity and reports it as text, JSON, or SARIF
  (`--format`), with `--fail-on <severity>` for CI gating.

Still missing, planned next: prompt-injection-in-output detection, an
HTTP/Streamable transport (stdio only for now), and a live terminal
dashboard.

## Status

The schema-fuzz probe closes the full loop end to end: generate mutations,
call the real tool, classify the outcome (a healthy rejection, a silently
accepted invalid input, an internal error, a hang, or a crash), and emit a
scored Finding. Verified against a real MCP server (`cmd/example-server`),
including a mutation that genuinely crashes the target process and one that
genuinely hangs past the per-call timeout.

Known limitation: if one probe crashes a tool, mcp-xray doesn't reconnect.
The scan stops retrying further calls against *that* tool once it crashes,
but every remaining tool's (and every remaining probe's) first call can
still surface one "crash" finding of its own for the rest of the whole
scan - that's fallout from the connection already being dead, not an
independently discovered bug. Treat the *first* crash finding in a report
as the real one. (Tools are listed alphabetically regardless of
registration order, so in `example-server`, `leaky_counter` crashes first,
under the rate-limit probe's own burst, and poisons every tool and probe
after it - confirmed by disabling its panic and re-running, which lets
rate-limit finish cleanly against every tool and lets schema-fuzz's own
null-byte mutation against `process` become the scan's first crash
instead, exactly as it was before the rate-limit probe existed. Either
way, `slow_echo` and `throttled_echo` end up inheriting whichever crash
happened first, rather than showing their own genuine timeout or rejection
- the same fallout, just with a different, alphabetically-earlier trigger.)

The auth-bypass probe (`internal/probes/authbypass`) finds candidate fields
by name (`account_id`, `role`, `token`, and similar) rather than by any real
understanding of a tool's authorization model, so it can both miss a real
bypass hiding behind an oddly-named field and flag a field that only looks
identity-shaped. There's also no real credential to strip yet, since
HTTP/Streamable transport (where a bearer token would actually live) doesn't
exist - it tests the one thing that's testable against a stdio tool server
today: whether an implausible argument value is honored instead of rejected.
Verified against `get_account` in `cmd/example-server`, a tool that returns
account data for whatever `account_id` and `role` it's given with no check
at all - both a High `auth_bypass_identity` and a High `auth_bypass_privilege`
finding fire against it.

The rate-limit probe (`internal/probes/ratelimit`, a `probe.ServerProbe`
rather than a `probe.ToolProbe`) calls every tool with the same benign,
valid-looking arguments several times in a row and never attributes the
*first* call's outcome to the burst: a tool that's already broken,
already rejects, or is already blocked on one valid call isn't a
rate-limiting finding - schema-fuzz and auth-bypass already cover "this
tool is broken" on their own terms. Its "no rate limiting observed"
finding relies on a deliberately crude latency-growth heuristic (comparing
the burst's first half against its second), documented as such in
`ratelimit_probe.go`'s own threshold constants: a server whose real limit
only kicks in past the burst size, or one that just happens to slow down
for an unrelated reason, can fool it either way. `cmd/mcp-xray` runs it
*before* schema-fuzz/auth-bypass specifically so its burst (and the
latency it measures) lands on a still-fresh connection rather than one
already hammered by adversarial payloads. Verified against
`cmd/example-server`: `get_account` and `greet` (no rate limiting at all)
each flag Low `rate_limit_absent`; `leaky_counter` (crashes on its 4th
call, simulating unbounded resource use under load) flags High
`rate_limit_dos`; `delete_all_records` flags Info `rate_limit_skipped_unsafe`,
same as the other two probes; and `throttled_echo` (a well-behaved tool
that rejects calls past its 3rd) produces no finding at all, confirmed by
a dedicated unit test since `leaky_counter`'s crash - alphabetically
earlier - ends the live connection before the probe's own loop reaches it
in a default run.

Still missing: a prompt-injection-in-output probe; the live terminal
dashboard; an HTTP/Streamable transport; and caching the compiled WASI
module across probe runs (every sandboxed call currently recompiles it,
which is correct but slow).

### Hardening against the server it's scanning

mcp-xray's own threat model is that the MCP server being scanned may be
malicious or compromised, not just buggy - so mcp-xray has to defend
itself against that server, not only probe it. A security-tooling-focused
pass found and fixed several gaps in that:

- The WASI sandbox had no execution deadline or memory cap. `ctx`
  cancellation in wazero is cooperative, not preemptive, so a probe stuck
  in a loop (driven by an adversarial input) could hang its goroutine
  forever. `Run` now enforces both (`WithCloseOnContextDone`, a 16MiB
  memory limit).
- A schema with an enormous number of properties could make the
  schema-fuzz probe generate an unbounded number of mutations - each one
  a real `CallTool` against the target, one of them a 100KB string.
  Capped at 200 fields.
- A tool's own response (or error text) was copied verbatim into a
  Finding's `Evidence` with no length limit. Capped at 2000 bytes.
- The text report printed `ServerName`, `ServerVersion`, a tool's name,
  and `Evidence` - all attacker-controlled - straight to the terminal. A
  malicious server could embed ANSI escape sequences (some terminals
  interpret these as commands) or forge fake report lines via embedded
  newlines. Now sanitized; JSON/SARIF needed no change since
  `encoding/json` already escapes control characters.
- `Snapshot`'s pagination had no cap on page count, so a server
  returning an endless `nextCursor` could grow it (and the scan that
  follows) without bound. Capped at 10,000 tools/resources/prompts.
- The Go toolchain itself was on go1.26.5, which `govulncheck` showed has
  15 reachable standard-library vulnerabilities (`net/http`,
  `crypto/tls`, `crypto/x509`, `net/url`, `net/textproto`,
  `encoding/asn1`). Upgraded to go1.26.11; `govulncheck ./...` now
  reports none.

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
  probes/            WASI probe sources (compiled by scripts/build-probes.sh):
                     schemafuzz/, authbypass/, and ratelimit/

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
                     and adapts each into a probe.ToolProbe/ServerProbe
                     (schemafuzz_probe.go, authbypass_probe.go,
                     ratelimit_probe.go)
  probes/schemashape/ the schema-fill helpers schemafuzz/authbypass/ratelimit
                     all share: parse a flat object schema, cap it, build a
                     minimal valid-looking argument set
  probes/schemafuzz/ the schema-fuzz mutation generator (plain Go, natively testable)
  probes/authbypass/ the auth-bypass mutation generator (plain Go, natively testable)
  probes/ratelimit/  the rate-limit probe's benign-baseline generator (plain
                     Go, natively testable)
  sandbox/           runs a probe's .wasm as a sandboxed WASI module via wazero
```
