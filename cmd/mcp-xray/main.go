// Command mcp-xray connects to an MCP server, introspects it, and runs
// security probes against what it finds.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/mbishflavien/mcp-xray/builtinprobes"
	"github.com/mbishflavien/mcp-xray/internal/inspector"
	"github.com/mbishflavien/mcp-xray/internal/safety"
	"github.com/mbishflavien/mcp-xray/probe"
	"github.com/mbishflavien/mcp-xray/report"
	"github.com/mbishflavien/mcp-xray/scan"
)

// allowToolFlag collects repeated -allow-tool flags.
type allowToolFlag []string

func (f *allowToolFlag) String() string { return strings.Join(*f, ",") }
func (f *allowToolFlag) Set(value string) error {
	*f = append(*f, value)
	return nil
}

func main() {
	code, err := run(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "mcp-xray:", err)
		os.Exit(1)
	}
	os.Exit(code)
}

// run parses args, runs the scan, and returns the process exit code the
// --fail-on threshold implies. It returns a non-nil error only for a
// usage/setup failure (bad flags, can't connect, etc.), which main()
// reports and always exits 1 for.
func run(args []string) (int, error) {
	fs := flag.NewFlagSet("mcp-xray", flag.ContinueOnError)
	format := fs.String("format", "text", "report format: text, json, or sarif")
	failOn := fs.String("fail-on", "none", "exit with status 1 if a finding at or above this severity exists (none, info, low, medium, high, critical)")
	timeout := fs.Duration("timeout", 5*time.Second, "per-call timeout for each probe request")
	allowDestructive := fs.Bool("allow-destructive", false, "disable the destructive-tool-name safety gate entirely")
	var allowTools allowToolFlag
	fs.Var(&allowTools, "allow-tool", "allow calling this tool even if its name looks destructive (repeatable)")
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "usage: mcp-xray [flags] -- <command to start the MCP server> [args...]")
		fs.PrintDefaults()
	}

	splitAt := indexOf(args, "--")
	if splitAt < 0 {
		return 0, fmt.Errorf("usage: mcp-xray [flags] -- <command to start the MCP server> [args...]")
	}
	if err := fs.Parse(args[:splitAt]); err != nil {
		return 0, err
	}
	serverCmd := args[splitAt+1:]
	if len(serverCmd) == 0 {
		return 0, fmt.Errorf("no server command given after --")
	}

	outputFormat, err := report.ParseFormat(*format)
	if err != nil {
		return 0, err
	}
	failOnSeverity, failOnSet, err := report.ParseFailOn(*failOn)
	if err != nil {
		return 0, err
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	session, err := inspector.ConnectCommand(ctx, serverCmd[0], serverCmd[1:]...)
	if err != nil {
		return 0, err
	}
	defer session.Close()

	capSnap, err := session.Snapshot(ctx)
	if err != nil {
		return 0, fmt.Errorf("introspect server: %w", err)
	}
	snap := probe.Snapshot{
		ServerName:    capSnap.ServerName,
		ServerVersion: capSnap.ServerVersion,
		Tools:         capSnap.Tools,
		Resources:     capSnap.Resources,
		Prompts:       capSnap.Prompts,
	}

	policy := safety.NewKeywordPolicy()
	policy.AllowAll = *allowDestructive
	policy.Allowlist = make(map[string]bool, len(allowTools))
	for _, name := range allowTools {
		policy.Allowlist[name] = true
	}

	runner := scan.NewRunner([]probe.Probe{builtinprobes.SchemaFuzz()}, scan.Options{
		CallTimeout: *timeout,
		Policy:      policy,
	})

	findingsOut, scanErr := runner.Run(ctx, session, snap)
	if scanErr != nil {
		fmt.Fprintln(os.Stderr, "mcp-xray: probe error:", scanErr)
	}

	writer, err := report.WriterFor(outputFormat)
	if err != nil {
		return 0, err
	}
	if err := writer.Write(os.Stdout, report.Result{
		ServerName:    snap.ServerName,
		ServerVersion: snap.ServerVersion,
		Findings:      findingsOut,
	}); err != nil {
		return 0, fmt.Errorf("write report: %w", err)
	}

	return report.ExitCode(findingsOut, failOnSeverity, failOnSet), nil
}

func indexOf(args []string, target string) int {
	for i, a := range args {
		if a == target {
			return i
		}
	}
	return -1
}
