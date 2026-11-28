package probe

import (
	"context"
	"errors"
	"io"

	"github.com/mbishflavien/mcp-xray/findings"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Outcome classifies what happened when a probe called a tool with one
// adversarial mutation. The bucketing follows what comparable fuzzers
// (e.g. mcp-gauntlet's mcp-fuzz) use: a crash or hang is the most severe
// thing a malformed input can cause, an internal-error response is next,
// and an invalid input that was silently accepted is a correctness smell
// but not a crash.
type Outcome int

const (
	// OutcomeToolError means the server validated the mutation and
	// rejected it the normal way (an IsError result, or a non-internal
	// JSON-RPC error such as InvalidParams). This is the expected,
	// healthy outcome for a malformed input and is not reportable.
	OutcomeToolError Outcome = iota
	// OutcomeAcceptedInvalid means the call "succeeded" even though the
	// input was malformed: the server didn't validate it.
	OutcomeAcceptedInvalid
	// OutcomeInternalError means the server responded with a JSON-RPC
	// internal-error code, suggesting the malformed input reached code
	// that wasn't expecting it.
	OutcomeInternalError
	// OutcomeTimeout means our own per-call timeout fired: the server
	// hung processing the mutation.
	OutcomeTimeout
	// OutcomeCrash means the connection to the server died mid-call, or
	// the failure mode couldn't be classified as anything safer.
	OutcomeCrash
	// OutcomeSkippedUnsafe means a SafetyPolicy blocked the call before
	// it was made.
	OutcomeSkippedUnsafe
)

func (o Outcome) String() string {
	switch o {
	case OutcomeAcceptedInvalid:
		return "accepted_invalid"
	case OutcomeInternalError:
		return "internal_error"
	case OutcomeTimeout:
		return "timeout"
	case OutcomeCrash:
		return "crash"
	case OutcomeSkippedUnsafe:
		return "skipped_unsafe"
	default:
		return "tool_error"
	}
}

// Severity maps an Outcome to a Finding severity.
func (o Outcome) Severity() findings.Severity {
	switch o {
	case OutcomeCrash, OutcomeTimeout:
		return findings.High
	case OutcomeInternalError:
		return findings.Medium
	case OutcomeAcceptedInvalid:
		return findings.Low
	default: // OutcomeToolError, OutcomeSkippedUnsafe
		return findings.Info
	}
}

// Reportable says whether this Outcome should become a Finding at all.
// OutcomeToolError means the server behaved correctly, which is a pass,
// not a finding.
func (o Outcome) Reportable() bool {
	return o != OutcomeToolError
}

// codeRejectedByTransport is the JSON-RPC error code the go-sdk's
// Streamable HTTP client uses to wrap a transport-level failure (a dead
// connection, a dial error, a non-2xx HTTP status with no JSON-RPC body)
// as a *jsonrpc.Error - internally jsonrpc2.ErrRejected, which isn't
// exported outside an internal package, so the code is checked directly
// instead. Documented in the go-sdk's own source as "rejected by
// transport" and stable (it's part of the wire-level contract between
// the transport and the generic jsonrpc2 layer, not an implementation
// detail likely to change silently).
const codeRejectedByTransport = -32005

// Classify turns a tool-call result/error pair into an Outcome. It never
// silently drops an unrecognized failure: anything it doesn't specifically
// recognize is treated as OutcomeCrash, since under-reporting a real
// problem is worse than over-reporting one.
func Classify(result *mcp.CallToolResult, err error) Outcome {
	if _, ok := errors.AsType[*BlockedError](err); ok {
		return OutcomeSkippedUnsafe
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return OutcomeTimeout
	}
	if errors.Is(err, mcp.ErrConnectionClosed) ||
		errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrClosedPipe) ||
		errors.Is(err, io.ErrUnexpectedEOF) {
		return OutcomeCrash
	}

	if rpcErr, ok := errors.AsType[*jsonrpc.Error](err); ok {
		if rpcErr.Code == codeRejectedByTransport {
			// The call never reached the server, or its response never
			// came back - a dead connection, a dial failure, a non-2xx
			// HTTP status with no JSON-RPC body to explain it. The
			// Streamable HTTP client wraps all of these as a *jsonrpc.Error
			// with this code so the jsonrpc2 layer doesn't tear down the
			// whole session over what might be transient - but from here,
			// it's exactly the kind of connection failure OutcomeCrash
			// exists for, not a tool's own validated rejection. Without
			// this check, a server dying mid-scan over HTTP would read as
			// a healthy "rejected the bad input" on every call afterward
			// instead of the crash it actually is.
			return OutcomeCrash
		}
		if rpcErr.Code == jsonrpc.CodeInternalError {
			return OutcomeInternalError
		}
		return OutcomeToolError
	}

	if err != nil {
		// An error we don't recognize. Fail safe rather than assume it's
		// benign.
		return OutcomeCrash
	}
	if result != nil && result.IsError {
		return OutcomeToolError
	}
	return OutcomeAcceptedInvalid
}
