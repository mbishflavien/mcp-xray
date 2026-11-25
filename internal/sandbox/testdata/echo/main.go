// Command echo is a trivial WASI fixture for sandbox tests: it copies
// stdin to stdout and exits. It is not one of mcp-xray's real probes and
// is not built by scripts/build-probes.sh; rebuild it manually with:
//
//	GOOS=wasip1 GOARCH=wasm go build -o ../echo.wasm .
package main

import (
	"io"
	"os"
)

func main() {
	io.Copy(os.Stdout, os.Stdin)
}
