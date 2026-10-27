package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/FolksyPizza/rig/internal/egress"
)

func loadEgressConfig(path string) (*egress.Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg egress.Config
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return egress.Compile(cfg)
}

// runProxy serves the egress proxy. SIGHUP re-reads the configuration, so Rig
// can change a running sandbox's allowlist without restarting the proxy (and
// without changing its address).
func runProxy(args []string) error {
	fs := flag.NewFlagSet("proxy", flag.ContinueOnError)
	cfgPath := fs.String("config", "/etc/rig/egress.json", "configuration file")
	listen := fs.String("listen", "", "listen address (overrides the config)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	pol, err := loadEgressConfig(*cfgPath)
	if err != nil {
		return err
	}
	addr := *listen
	if addr == "" {
		addr = pol.Config().Listen
	}
	if addr == "" {
		addr = ":3128"
	}

	srv := egress.NewServer(pol, os.Stdout, nil, nil)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			next, err := loadEgressConfig(*cfgPath)
			status := map[string]string{"ts": time.Now().UTC().Format(time.RFC3339Nano), "event": "config", "action": "reloaded"}
			if err != nil {
				status["action"] = "reload_failed"
				status["error"] = err.Error()
			} else {
				srv.SetPolicy(next)
			}
			b, _ := json.Marshal(status)
			fmt.Fprintln(os.Stdout, string(b))
		}
	}()

	return srv.Listen(ctx, addr)
}

// runProbe tries each address in parallel and prints "open ADDR" or
// "closed ADDR: reason" for each, in order. It exits 0 only when every
// address accepted a TCP connection. Rig uses it as a readiness check (the
// helper image has no shell) and in 'rig doctor --deep' to confirm what a
// sandbox network cannot reach.
func runProbe(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: rig-helper probe HOST:PORT...")
	}
	results := make([]error, len(args))
	var wg sync.WaitGroup
	for i, addr := range args {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := net.DialTimeout("tcp", addr, 2*time.Second)
			if err == nil {
				_ = c.Close()
			}
			results[i] = err
		}()
	}
	wg.Wait()
	closed := 0
	for i, addr := range args {
		if results[i] != nil {
			closed++
			fmt.Printf("closed %s: %v\n", addr, results[i])
		} else {
			fmt.Printf("open %s\n", addr)
		}
	}
	if closed > 0 {
		return fmt.Errorf("%d of %d addresses did not accept a connection", closed, len(args))
	}
	return nil
}

// runResolve exits 0 when the name resolves. 'rig doctor --deep' uses it to
// confirm that a sandbox network cannot look up outside names, which would
// otherwise be a way to send data out through DNS.
func runResolve(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: rig-helper resolve NAME")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupHost(ctx, args[0])
	if err != nil {
		return err
	}
	fmt.Println(strings.Join(addrs, " "))
	return nil
}
