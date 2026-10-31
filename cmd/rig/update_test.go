package main

import "testing"

func TestChecksumFor(t *testing.T) {
	sums := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  rig-linux-amd64\n" +
		"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB *rig-darwin-arm64\n" +
		"short  rig-linux-arm64\n"
	if got := checksumFor(sums, "rig-linux-amd64"); got != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Errorf("linux: %q", got)
	}
	if got := checksumFor(sums, "rig-darwin-arm64"); got != "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" {
		t.Errorf("binary-mode line: %q", got)
	}
	if checksumFor(sums, "rig-linux-arm64") != "" || checksumFor(sums, "rig-linux") != "" {
		t.Error("malformed or missing entries must not match")
	}
}

func TestHelpIsOneScreen(t *testing.T) {
	if quickStart == "" {
		t.Fatal("no quick start")
	}
}
