package provider

import "testing"

func TestParseSize(t *testing.T) {
	cases := map[string]int64{
		"100MiB": 100 << 20,
		"2GiB":   2 << 30,
		"512KiB": 512 << 10,
		"1.5GiB": int64(1.5 * (1 << 30)),
		"0B":     0,
		"--":     0,
	}
	for in, want := range cases {
		if got := parseSize(in); got != want {
			t.Errorf("parseSize(%q) = %d, want %d", in, got, want)
		}
	}
}

func TestParseCLIStats(t *testing.T) {
	s, err := parseCLIStats("12.50%\t100MiB / 2GiB\t7\n")
	if err != nil {
		t.Fatal(err)
	}
	if s.CPUPercent != 12.5 {
		t.Errorf("cpu = %v", s.CPUPercent)
	}
	if s.MemBytes != 100<<20 || s.MemLimit != 2<<30 {
		t.Errorf("mem = %d / %d", s.MemBytes, s.MemLimit)
	}
	if s.PIDs != 7 {
		t.Errorf("pids = %d", s.PIDs)
	}
}

func TestParseCLIStatsBad(t *testing.T) {
	if _, err := parseCLIStats("garbage"); err == nil {
		t.Fatal("expected error on malformed stats")
	}
}

func TestDetectPrefersNativePerOS(t *testing.T) {
	all := func(string) bool { return true }
	if p := detect("darwin", all); p.Name() != "apple" {
		t.Errorf("darwin should prefer apple, got %s", p.Name())
	}
	if p := detect("linux", all); p.Name() != "podman" {
		t.Errorf("linux should prefer podman, got %s", p.Name())
	}
	if p := detect("windows", all); p.Name() != "podman" {
		t.Errorf("windows should prefer podman, got %s", p.Name())
	}
	// Falls back down the chain when the preferred one is absent.
	onlyDocker := func(b string) bool { return b == "docker" }
	if p := detect("darwin", onlyDocker); p.Name() != "docker" {
		t.Errorf("should fall back to docker, got %s", p.Name())
	}
}

func TestParseAppleNames(t *testing.T) {
	names := parseAppleNames([]byte(`[{"name":"rig-a"},{"id":"rig-b"}]`))
	if len(names) != 2 || names[0] != "rig-a" || names[1] != "rig-b" {
		t.Errorf("names = %v", names)
	}
}
