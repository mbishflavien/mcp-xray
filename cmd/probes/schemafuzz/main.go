// Command schemafuzz is compiled to a WASI module (GOOS=wasm GOARCH=wasip1)
// and run sandboxed by the host via wazero. It never touches the network or
// filesystem: it reads a probeproto.SchemaFuzzInput on stdin and writes a
// probeproto.SchemaFuzzOutput to stdout.
package main

import (
	"encoding/json"
	"io"
	"os"

	"github.com/mbishflavien/mcp-xray/internal/probeproto"
	"github.com/mbishflavien/mcp-xray/internal/probes/schemafuzz"
)

func main() {
	in, err := io.ReadAll(os.Stdin)
	if err != nil {
		writeOutput(probeproto.SchemaFuzzOutput{Error: "read stdin: " + err.Error()})
		return
	}

	var input probeproto.SchemaFuzzInput
	if err := json.Unmarshal(in, &input); err != nil {
		writeOutput(probeproto.SchemaFuzzOutput{Error: "parse input: " + err.Error()})
		return
	}

	mutations, errMsg := schemafuzz.Generate(input.ToolName, input.Schema)
	writeOutput(probeproto.SchemaFuzzOutput{Mutations: mutations, Error: errMsg})
}

func writeOutput(out probeproto.SchemaFuzzOutput) {
	enc := json.NewEncoder(os.Stdout)
	_ = enc.Encode(out)
}
