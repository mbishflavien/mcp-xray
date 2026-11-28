# mcp-xray

A security and compliance inspector for [MCP](https://modelcontextprotocol.io) servers.

Point it at an MCP server - over stdio, or over HTTP (`--url`) - and it:

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
- Calls every tool once with a benign argument set and inspects the
  response text for content shaped like an attempt to hijack whatever LLM
  reads it next: override phrases, forged chat-template delimiters,
  exfiltration directives, or invisible Unicode tricks.
- Gates every call through a destructive-tool-name safety policy first, so a
  probe can't actually invoke something like `delete_all_records` without an
  explicit `--allow-tool` opt-in.
- Scores the outcome by severity and reports it as text, JSON, or SARIF
  (`--format`), with `--fail-on <severity>` for CI gating.

Still missing, planned next: a live terminal dashboard.

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
identity-shaped. It still only forges values inside a tool's *arguments* -
even now that a real credential-bearing transport exists (`--url` with
`-header "Authorization: ..."`), there's no probe yet that tries stripping
or tampering with a transport-level credential; it tests the one thing
that's testable today regardless of transport: whether an implausible
argument value is honored instead of rejected.
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

The prompt-injection probe (`internal/probes/promptinjection`) calls each
tool once with a benign argument set - reusing `BaselineArgs`, the same
generator the rate-limit probe uses, rather than compiling a fourth
near-identical WASI module - and, only if that call cleanly succeeds,
scans the response text for content shaped like an attempt to hijack
whatever LLM reads it next. It's the one probe with no WASI sandboxing of
its own: nothing in it parses a tool's schema, so there's no
attacker-controlled schema-parsing logic to protect; what it does bound is
how much of the (attacker-controlled, potentially huge) response text it
ever scans (`maxScanLen`, 50,000 bytes). Because the argument sent is
always the tool's own benign baseline, never one of schema-fuzz's
adversarial payloads, a match can never be mcp-xray's own probe string
reflected back - anything found is something the server chose to say on
its own. Four categories, each independently reportable:
`prompt_injection_instruction_override` and `_exfiltration` (High, each
with a small documented false-positive risk - see
`internal/probes/promptinjection/detect.go`); `_role_impersonation` and
`_hidden_content` (Critical, essentially never legitimate in real tool
output). Verified against `cmd/example-server`: `get_notes` (a note
combining an override phrase, a forged `<|system|>` delimiter, and an
exfiltration directive in one payload - realistic, since real
indirect-injection attempts often stack techniques) fires all three of
the first kinds; `get_signature` (a payload hidden entirely in zero-width
Unicode characters) fires `_hidden_content` alone; every other tool
produces no prompt-injection finding at all. A default scan doesn't show
this cleanly end to end - `leaky_counter`'s crash under the rate-limit
probe (which runs first) ends the connection before this probe's turn,
the same cascade the "known limitation" paragraph above describes - so
this was verified with a standalone runner built from the public API
(`scan.NewRunner` with only this probe) against the real
`cmd/example-server` binary, confirming the four findings above with no
other probe's crash in the way.

Still missing: the live terminal dashboard; and caching the compiled WASI
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
- The rate-limit probe multiplies calls by a burst factor - the one
  resource-use risk it introduces that schema-fuzz/auth-bypass don't
  have - so `BurstSize x toolCount x CallTimeout` could otherwise stack
  up unbounded on a server with many slow or hanging tools. `RunServer`
  now tracks its own wall-clock time and stops starting any *new* tool's
  burst past a ceiling (`MaxDuration`, 2 minutes by default); a burst
  already in progress still finishes.
- That same probe's burst loop now checks for cancellation between
  calls, so canceling a scan (Ctrl-C) stops a burst immediately instead
  of grinding through its remaining calls - and a cancellation never
  gets misreported as a rate-limit finding.
- The prompt-injection probe inspects a tool's own response text, which
  is fully attacker-controlled and can be arbitrarily large. Capped at
  50,000 bytes (`maxScanLen`) before any pattern matching runs, and the
  evidence it reports is built from a small excerpt around the actual
  match rather than the whole response, so neither the scan itself nor
  the resulting report can be inflated by an oversized reply.

## Getting started

```bash
./scripts/build-probes.sh                       # compile WASI probes to internal/probes/bin/*.wasm
go build -o bin/mcp-xray ./cmd/mcp-xray
go build -o bin/example-server ./cmd/example-server   # a minimal MCP server to try it on

./bin/mcp-xray -- ./bin/example-server
./bin/mcp-xray --format sarif --fail-on high -- ./bin/example-server
./bin/mcp-xray --allow-tool delete_all_records -- ./bin/example-server
```

`go test ./...` instantiates a fresh WASI runtime per sandboxed call (no
caching across probe runs yet - see "Still missing" above), and
`internal/probes`'s own test suite makes dozens of these back to back.
On a memory-constrained machine this can produce a spurious `module
closed with context deadline exceeded` - the sandbox's own timeout
firing because instantiation itself was slow, not a failure in the code
under test. If you hit that, re-run `internal/probes`'s tests in smaller
batches (`go test ./internal/probes/ -run TestSchemaFuzz`, then
`-run TestAuthBypass`, and so on) rather than treating it as a real
failure.

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
                     ratelimit_probe.go, promptinjection_probe.go)
  probes/schemashape/ the schema-fill helpers schemafuzz/authbypass/ratelimit
                     all share: parse a flat object schema, cap it, build a
                     minimal valid-looking argument set
  probes/schemafuzz/ the schema-fuzz mutation generator (plain Go, natively testable)
  probes/authbypass/ the auth-bypass mutation generator (plain Go, natively testable)
  probes/ratelimit/  the rate-limit probe's benign-baseline generator (plain
                     Go, natively testable)
  probes/promptinjection/ the prompt-injection probe's pattern matcher
                     (plain Go, natively testable, no WASI - nothing in it
                     parses a schema, so there's nothing to sandbox)
  sandbox/           runs a probe's .wasm as a sandboxed WASI module via wazero
```
