package mcpguard

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"os/exec"
	"sync"
)

// RunStdio runs cmd as a stdio MCP server and relays newline-delimited
// JSON-RPC between in/out (the agent) and the child, applying f in both
// directions. It returns when the child exits; the exit code is returned so
// the caller can propagate it. cmd.Stderr should be set by the caller.
func RunStdio(f *Filter, cmd *exec.Cmd, in io.Reader, out io.Writer) (int, error) {
	childIn, err := cmd.StdinPipe()
	if err != nil {
		return 1, err
	}
	childOut, err := cmd.StdoutPipe()
	if err != nil {
		return 1, err
	}
	if err := cmd.Start(); err != nil {
		return 127, err
	}

	var outMu sync.Mutex
	writeOut := func(b []byte) {
		outMu.Lock()
		defer outMu.Unlock()
		_, _ = out.Write(append(append([]byte{}, b...), '\n'))
	}

	// Agent -> server.
	go func() {
		defer childIn.Close()
		eachLine(in, func(line []byte) bool {
			fwd, reply := f.FromClient(line)
			if reply != nil {
				writeOut(reply)
			}
			if fwd != nil {
				if _, err := childIn.Write(append(append([]byte{}, fwd...), '\n')); err != nil {
					return false
				}
			}
			return true
		})
	}()

	// Server -> agent. Finishing this loop means the child closed stdout.
	eachLine(childOut, func(line []byte) bool {
		writeOut(f.FromServer(line))
		return true
	})

	err = cmd.Wait()
	var ee *exec.ExitError
	switch {
	case err == nil:
		return 0, nil
	case errors.As(err, &ee):
		return ee.ExitCode(), nil
	default:
		return 1, err
	}
}

// eachLine calls fn for every non-empty line in r until EOF or fn returns
// false. Lines are not length-limited: MCP messages can carry large payloads.
func eachLine(r io.Reader, fn func([]byte) bool) {
	br := bufio.NewReaderSize(r, 64*1024)
	for {
		line, err := br.ReadBytes('\n')
		line = bytes.TrimRight(line, "\r\n")
		if len(line) > 0 && !fn(line) {
			return
		}
		if err != nil {
			return
		}
	}
}
