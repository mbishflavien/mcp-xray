package probe

import (
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// SafetyPolicy decides whether a tool is safe to actually call with
// adversarial arguments. mcp-xray calls real tools on a real server, so
// without a gate a probe could, say, invoke a tool literally named
// delete_all_records while fuzzing it.
type SafetyPolicy interface {
	// Allow reports whether tool may be called. When it returns false,
	// reason explains why, for use in a BlockedError or a Finding.
	Allow(tool *mcp.Tool) (ok bool, reason string)
}

// BlockedError is returned by a gated ToolCaller instead of making the
// real call when a SafetyPolicy blocks a tool. Classify recognizes it via
// errors.As and maps it to OutcomeSkippedUnsafe.
type BlockedError struct {
	Tool   string
	Reason string
}

func (e *BlockedError) Error() string {
	return fmt.Sprintf("tool %q blocked: %s", e.Tool, e.Reason)
}
