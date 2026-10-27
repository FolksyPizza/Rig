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
	if p := detect("darwin", all, false); p.Name() != "apple" {
		t.Errorf("darwin should prefer apple, got %s", p.Name())
	}
	if p := detect("linux", all, false); p.Name() != "podman" {
		t.Errorf("linux should prefer podman, got %s", p.Name())
	}
	if p := detect("windows", all, false); p.Name() != "podman" {
		t.Errorf("windows should prefer podman, got %s", p.Name())
	}
	// Falls back down the chain when the preferred one is absent.
	onlyDocker := func(b string) bool { return b == "docker" }
	if p := detect("darwin", onlyDocker, false); p.Name() != "docker" {
		t.Errorf("should fall back to docker, got %s", p.Name())
	}
}

func TestParseAppleNames(t *testing.T) {
	names := parseAppleNames([]byte(`[{"configuration":{"id":"rig-a"}},{"configuration":{"id":"rig-b"}}]`))
	if len(names) != 2 || names[0] != "rig-a" || names[1] != "rig-b" {
		t.Errorf("names = %v", names)
	}
}

func TestParseAppleStats(t *testing.T) {
	s, err := parseAppleStats([]byte(`[{"id":"x","memoryUsageBytes":4317184,"memoryLimitBytes":1073741824,"numProcesses":3}]`))
	if err != nil {
		t.Fatal(err)
	}
	if s.MemBytes != 4317184 || s.MemLimit != 1073741824 || s.PIDs != 3 {
		t.Errorf("stats = %+v", s)
	}
}

func TestDetectPrefersIsolationCapableEngines(t *testing.T) {
	all := func(string) bool { return true }
	if p := detect("darwin", all, true); p.Name() != "podman" {
		t.Errorf("a profile needing network isolation should not get apple, got %s", p.Name())
	}
	onlyApple := func(b string) bool { return b == "container" }
	if p := detect("darwin", onlyApple, true); p.Name() != "apple" {
		t.Errorf("apple is still the fallback, got %s", p.Name())
	}
}

func TestEngineRuntimeMatchers(t *testing.T) {
	for _, n := range []string{"runsc", "runsc-kvm", "io.containerd.runsc.v1"} {
		if !IsGVisor(n) {
			t.Errorf("IsGVisor(%q) = false", n)
		}
	}
	for _, n := range []string{"kata", "kata-qemu", "io.containerd.kata.v2"} {
		if !IsKata(n) {
			t.Errorf("IsKata(%q) = false", n)
		}
	}
	if IsGVisor("runc") || IsKata("crun") {
		t.Error("ordinary runtimes must not match")
	}
	info := EngineInfo{Runtimes: []string{"runc", "runsc"}}
	if name, ok := info.HasRuntime(IsGVisor); !ok || name != "runsc" {
		t.Errorf("HasRuntime = %q %v", name, ok)
	}
}
