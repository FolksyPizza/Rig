package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/FolksyPizza/rig/internal/gateway"
	"github.com/FolksyPizza/rig/internal/mcpguard"
)

// runGateway serves MCP bridges, the git broker and relayed host ports.
// Audit lines go to stderr; stdout is reserved for the relay stream.
func runGateway(args []string) error {
	protectProcess()
	fs := flag.NewFlagSet("gateway", flag.ContinueOnError)
	cfgPath := fs.String("config", "/etc/rig/gateway.json", "configuration file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	data, err := os.ReadFile(*cfgPath)
	if err != nil {
		return err
	}
	var cfg gateway.Config
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return fmt.Errorf("parse %s: %w", *cfgPath, err)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	return gateway.Run(ctx, cfg, os.Stdin, os.Stdout, os.Stderr, os.Getenv)
}

// runGuard wraps a stdio MCP server that runs inside the sandbox. The agent
// launches rig-helper instead of the server; tool calls are checked and
// recorded on the way through.
func runGuard(args []string) error {
	fs := flag.NewFlagSet("mcp-guard", flag.ContinueOnError)
	policyPath := fs.String("policy", "", "policy file (JSON)")
	logPath := fs.String("log", "", "audit log file (default $HOME/.rig/mcp-audit.jsonl)")
	envFile := fs.String("env-file", "", "KEY=VALUE file of extra variables for the server (skipped if missing)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cmdArgs := fs.Args()
	if len(cmdArgs) == 0 {
		return fmt.Errorf("usage: rig-helper mcp-guard --policy FILE -- CMD [ARGS...]")
	}

	var pol mcpguard.Policy
	if *policyPath != "" {
		data, err := os.ReadFile(*policyPath)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(data, &pol); err != nil {
			return fmt.Errorf("parse %s: %w", *policyPath, err)
		}
	}
	if err := pol.Validate(); err != nil {
		return err
	}

	path := *logPath
	if path == "" {
		home, _ := os.UserHomeDir()
		path = filepath.Join(home, ".rig", "mcp-audit.jsonl")
	}
	logger := gateway.NewLogger(os.Stderr)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err == nil {
		if f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600); err == nil {
			defer f.Close()
			logger = gateway.NewLogger(f)
		}
	}

	cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()
	for k, v := range pol.Env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	if *envFile != "" {
		extra, err := readEnvFile(*envFile)
		if err != nil {
			return err
		}
		cmd.Env = append(cmd.Env, extra...)
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	go func() {
		for s := range sigs {
			if cmd.Process != nil {
				_ = cmd.Process.Signal(s)
			}
		}
	}()

	filter := mcpguard.NewFilter(pol, func(e mcpguard.Event) { logger.Log(e) })
	code, err := mcpguard.RunStdio(filter, cmd, os.Stdin, os.Stdout)
	if err != nil {
		return err
	}
	if code != 0 {
		return exitCode(code)
	}
	return nil
}

// readEnvFile reads KEY=VALUE lines. A missing file means no extra variables.
func readEnvFile(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		if k, _, ok := strings.Cut(line, "="); ok && k != "" && !strings.HasPrefix(k, "#") {
			out = append(out, line)
		}
	}
	return out, nil
}
