package report

import (
	"encoding/json"
	"io"
)

type jsonWriter struct{}

// JSON returns a Writer that renders a Result as indented JSON.
func JSON() Writer { return jsonWriter{} }

func (jsonWriter) Write(w io.Writer, r Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}
