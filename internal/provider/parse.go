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

// Apple `container ls --format json` nests the name under configuration.id.
func parseAppleNames(data []byte) []string {
	var items []struct {
		Configuration struct {
			ID string `json:"id"`
		} `json:"configuration"`
		ID string `json:"id"`
	}
	if json.Unmarshal(data, &items) != nil {
		return nil
	}
	var names []string
	for _, it := range items {
		if it.Configuration.ID != "" {
			names = append(names, it.Configuration.ID)
		} else if it.ID != "" {
			names = append(names, it.ID)
		}
	}
	return names
}

// Apple `container stats --format json` returns an array of samples with explicit
// byte/count fields (memoryUsageBytes, memoryLimitBytes, numProcesses).
func parseAppleStats(data []byte) (Stats, error) {
	var arr []struct {
		ID               string  `json:"id"`
		MemoryUsageBytes int64   `json:"memoryUsageBytes"`
		MemoryLimitBytes int64   `json:"memoryLimitBytes"`
		NumProcesses     int     `json:"numProcesses"`
		CPUUsageUsec     float64 `json:"cpuUsageUsec"`
	}
	if err := json.Unmarshal(data, &arr); err != nil || len(arr) == 0 {
		return Stats{}, fmt.Errorf("unrecognized apple stats json: %w", err)
	}
	s := arr[0]
	return Stats{
		MemBytes: s.MemoryUsageBytes,
		MemLimit: s.MemoryLimitBytes,
		PIDs:     s.NumProcesses,
	}, nil
}
