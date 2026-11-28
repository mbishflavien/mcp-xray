package probe

import (
	"context"
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/mbishflavien/mcp-xray/findings"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestClassify(t *testing.T) {
	cases := []struct {
		name   string
		result *mcp.CallToolResult
		err    error
		want   Outcome
	}{
		{
			name: "blocked by safety policy",
			err:  &BlockedError{Tool: "delete_all", Reason: "destructive name"},
			want: OutcomeSkippedUnsafe,
		},
		{
			name: "our own timeout fired",
			err:  context.DeadlineExceeded,
			want: OutcomeTimeout,
		},
		{
			name: "connection closed",
			err:  mcp.ErrConnectionClosed,
			want: OutcomeCrash,
		},
		{
			name: "unexpected EOF reading from a dead process",
			err:  io.ErrUnexpectedEOF,
			want: OutcomeCrash,
		},
		{
			name: "JSON-RPC internal error",
			err:  &jsonrpc.Error{Code: jsonrpc.CodeInternalError, Message: "boom"},
			want: OutcomeInternalError,
		},
		{
			name: "JSON-RPC invalid params, a healthy rejection",
			err:  &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: "bad arg"},
			want: OutcomeToolError,
		},
		{
			// Streamable HTTP's client wraps a dead connection, a dial
			// failure, or an unexplained non-2xx HTTP status as exactly
			// this *jsonrpc.Error - never a real response from the tool
			// itself, so it must not be classified the same way a genuine
			// rejection like CodeInvalidParams above is.
			name: "HTTP transport rejected the call outright (dead connection)",
			err:  fmt.Errorf("sending %q: rejected by transport: %w", "tools/call", &jsonrpc.Error{Code: codeRejectedByTransport, Message: "rejected by transport"}),
			want: OutcomeCrash,
		},
		{
			name:   "tool reported its own error",
			result: &mcp.CallToolResult{IsError: true},
			want:   OutcomeToolError,
		},
		{
			name:   "call succeeded with no validation",
			result: &mcp.CallToolResult{IsError: false},
			want:   OutcomeAcceptedInvalid,
		},
		{
			name: "an error we don't recognize is treated as a crash",
			err:  errors.New("something unexpected"),
			want: OutcomeCrash,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Classify(tc.result, tc.err); got != tc.want {
				t.Errorf("Classify() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestOutcomeSeverity(t *testing.T) {
	cases := []struct {
		outcome Outcome
		want    findings.Severity
	}{
		{OutcomeCrash, findings.High},
		{OutcomeTimeout, findings.High},
		{OutcomeInternalError, findings.Medium},
		{OutcomeAcceptedInvalid, findings.Low},
		{OutcomeToolError, findings.Info},
		{OutcomeSkippedUnsafe, findings.Info},
	}
	for _, tc := range cases {
		if got := tc.outcome.Severity(); got != tc.want {
			t.Errorf("%v.Severity() = %v, want %v", tc.outcome, got, tc.want)
		}
	}
}

func TestOutcomeReportable(t *testing.T) {
	if OutcomeToolError.Reportable() {
		t.Error("OutcomeToolError should not be reportable: a healthy rejection is a pass")
	}
	for _, o := range []Outcome{
		OutcomeAcceptedInvalid, OutcomeInternalError, OutcomeTimeout,
		OutcomeCrash, OutcomeSkippedUnsafe,
	} {
		if !o.Reportable() {
			t.Errorf("%v should be reportable", o)
		}
	}
}
