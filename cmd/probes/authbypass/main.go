// Command authbypass is compiled to a WASI module (GOOS=wasm GOARCH=wasip1)
// and run sandboxed by the host via wazero. It never touches the network or
// filesystem: it reads a probeproto.MutationRequest on stdin and writes a
// probeproto.MutationResponse to stdout.
package main

import (
	"encoding/json"
	"io"
	"os"

	"github.com/mbishflavien/mcp-xray/internal/probeproto"
	"github.com/mbishflavien/mcp-xray/internal/probes/authbypass"
)

func main() {
	in, err := io.ReadAll(os.Stdin)
	if err != nil {
		writeOutput(probeproto.MutationResponse{Error: "read stdin: " + err.Error()})
		return
	}

	var input probeproto.MutationRequest
	if err := json.Unmarshal(in, &input); err != nil {
		writeOutput(probeproto.MutationResponse{Error: "parse input: " + err.Error()})
		return
	}

	mutations, errMsg := authbypass.Generate(input.ToolName, input.Schema)
	writeOutput(probeproto.MutationResponse{Mutations: mutations, Error: errMsg})
}

func writeOutput(out probeproto.MutationResponse) {
	enc := json.NewEncoder(os.Stdout)
	_ = enc.Encode(out)
}
