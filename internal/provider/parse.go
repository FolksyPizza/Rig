package provider

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// parseCLIStats parses a Docker/Podman `stats --format "{{.CPUPerc}}\t{{.MemUsage}}\t{{.PIDs}}"`
// line, e.g. "12.34%\t100MiB / 2GiB\t7".
func parseCLIStats(out string) (Stats, error) {
	line := lastNonEmpty(out)
	parts := strings.Split(line, "\t")
	if len(parts) < 3 {
		return Stats{}, fmt.Errorf("unexpected stats output: %q", out)
	}
	memBytes, memLimit := parseMemUsage(parts[1])
	pids, _ := strconv.Atoi(strings.TrimSpace(parts[2]))
	return Stats{
		CPUPercent: parsePercent(parts[0]),
		MemBytes:   memBytes,
		MemLimit:   memLimit,
		PIDs:       pids,
	}, nil
}

func parsePercent(s string) float64 {
	s = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(s), "%"))
	v, _ := strconv.ParseFloat(s, 64)
	return v
}

// parseMemUsage parses "100MiB / 2GiB" into (used, limit) bytes.
func parseMemUsage(s string) (int64, int64) {
	used, limit := s, ""
	if a, b, ok := strings.Cut(s, "/"); ok {
		used, limit = a, b
	}
	return parseSize(used), parseSize(limit)
}

var sizeUnits = []struct {
	suffix string
	mult   float64
}{
	{"gib", 1 << 30}, {"mib", 1 << 20}, {"kib", 1 << 10},
	{"gb", 1e9}, {"mb", 1e6}, {"kb", 1e3},
	{"g", 1 << 30}, {"m", 1 << 20}, {"k", 1 << 10},
	{"b", 1},
}

func parseSize(s string) int64 {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" || s == "--" {
		return 0
	}
	for _, u := range sizeUnits {
		if strings.HasSuffix(s, u.suffix) {
			num := strings.TrimSpace(strings.TrimSuffix(s, u.suffix))
			if v, err := strconv.ParseFloat(num, 64); err == nil {
				return int64(v * u.mult)
			}
			return 0
		}
	}
	v, _ := strconv.ParseFloat(s, 64)
	return int64(v)
}

func lastNonEmpty(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if t := strings.TrimSpace(lines[i]); t != "" {
			return t
		}
	}
	return ""
}

// --- Apple `container` JSON (schema is loose across versions; parse defensively) ---

func parseAppleNames(data []byte) []string {
	var items []map[string]any
	if json.Unmarshal(data, &items) != nil {
		return nil
	}
	var names []string
	for _, it := range items {
		for _, key := range []string{"name", "Name", "id", "ID"} {
			if v, ok := it[key].(string); ok && v != "" {
				names = append(names, v)
				break
			}
		}
	}
	return names
}

func parseAppleStats(data []byte) (Stats, error) {
	// Accept either a single object or a one-element array.
	var obj map[string]any
	if json.Unmarshal(data, &obj) != nil {
		var arr []map[string]any
		if json.Unmarshal(data, &arr) != nil || len(arr) == 0 {
			return Stats{}, fmt.Errorf("unrecognized apple stats json")
		}
		obj = arr[0]
	}
	num := func(keys ...string) float64 {
		for _, k := range keys {
			switch v := obj[k].(type) {
			case float64:
				return v
			case string:
				if f, err := strconv.ParseFloat(strings.TrimSuffix(v, "%"), 64); err == nil {
					return f
				}
			}
		}
		return 0
	}
	return Stats{
		CPUPercent: num("cpu", "cpu_percent", "CPUPercent"),
		MemBytes:   int64(num("memory", "mem_bytes", "MemoryBytes")),
		MemLimit:   int64(num("memory_limit", "mem_limit", "MemoryLimit")),
		PIDs:       int(num("pids", "PIDs")),
	}, nil
}
