//go:build linux

package main

import "syscall"

// protectProcess marks the process non-dumpable. The gateway holds the git
// broker's token and MCP servers' secrets in its environment, and the MCP
// servers it starts run as the same user; without this they could read the
// gateway's environment or memory through /proc.
func protectProcess() {
	_, _, _ = syscall.RawSyscall(syscall.SYS_PRCTL, syscall.PR_SET_DUMPABLE, 0, 0)
}
