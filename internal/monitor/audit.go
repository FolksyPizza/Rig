package monitor

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// Record is one line of a profile's audit log.
type Record struct {
	TS        string          `json:"ts"`
	Profile   string          `json:"profile"`
	Container string          `json:"container,omitempty"`
	Source    string          `json:"source"`
	Kind      string          `json:"kind"`
	Severity  string          `json:"severity"`
	Action    string          `json:"action"`
	Detail    string          `json:"detail"`
	Data      json.RawMessage `json:"data,omitempty"`
}

// maxAuditBytes is when the log rotates to audit.jsonl.1.
const maxAuditBytes = 20 << 20

// Audit appends records to a JSON-lines file readable only by you. It lives
// on the host, outside every container, so nothing in a sandbox can edit it.
type Audit struct {
	mu   sync.Mutex
	path string
	f    *os.File
	size int64
}

// OpenAudit opens (creating) the log, rotating it first if it is large.
func OpenAudit(path string) (*Audit, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if info, err := os.Stat(path); err == nil && info.Size() > maxAuditBytes {
		_ = os.Rename(path, path+".1")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	info, _ := f.Stat()
	a := &Audit{path: path, f: f}
	if info != nil {
		a.size = info.Size()
	}
	return a, nil
}

// Write appends one record.
func (a *Audit) Write(r Record) error {
	if a == nil {
		return nil
	}
	if len(r.Data) > 0 && !json.Valid(r.Data) {
		r.Data = nil
	}
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.f == nil {
		return fmt.Errorf("audit log closed")
	}
	if a.size+int64(len(b))+1 > maxAuditBytes {
		_ = a.f.Close()
		_ = os.Rename(a.path, a.path+".1")
		f, err := os.OpenFile(a.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			a.f = nil
			return err
		}
		a.f, a.size = f, 0
	}
	n, err := a.f.Write(append(b, '\n'))
	a.size += int64(n)
	return err
}

// Close closes the log.
func (a *Audit) Close() error {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.f == nil {
		return nil
	}
	err := a.f.Close()
	a.f = nil
	return err
}

// ReadAudit returns the last n records (all when n <= 0) from a log.
func ReadAudit(path string, n int) ([]Record, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return readRecords(f, n)
}

func readRecords(r io.Reader, n int) ([]Record, error) {
	var out []Record
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4<<20)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var rec Record
		if json.Unmarshal(line, &rec) != nil {
			continue
		}
		out = append(out, rec)
		if n > 0 && len(out) > n*2 {
			out = append([]Record{}, out[len(out)-n:]...)
		}
	}
	if n > 0 && len(out) > n {
		out = out[len(out)-n:]
	}
	return out, sc.Err()
}
