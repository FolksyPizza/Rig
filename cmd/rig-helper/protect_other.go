//go:build !linux

package main

// protectProcess is a no-op off Linux, where the helper never runs for real.
func protectProcess() {}
