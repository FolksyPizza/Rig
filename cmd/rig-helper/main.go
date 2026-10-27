// Command rig-helper runs the parts of Rig that live inside containers: the
// egress proxy, the MCP gateway, and the MCP tool-call guard.
//
// It is built from source inside an image build (see the root package's
// embedded source), so it must depend on the Go standard library only.
package main

import (
	"fmt"
	"os"
)

const usage = `rig-helper: Rig's in-container helper.

Usage:
  rig-helper proxy   --config FILE [--listen ADDR]   run the egress proxy
  rig-helper gateway --config FILE                   run the MCP and host gateway
  rig-helper mcp-guard --policy FILE [--log FILE] -- CMD [ARGS...]
                                                     wrap a stdio MCP server
  rig-helper probe ADDR...                           exit 0 if every ADDR accepts TCP
  rig-helper resolve NAME                            exit 0 if NAME resolves
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "proxy":
		err = runProxy(os.Args[2:])
	case "gateway":
		err = runGateway(os.Args[2:])
	case "mcp-guard":
		err = runGuard(os.Args[2:])
	case "probe":
		err = runProbe(os.Args[2:])
	case "resolve":
		err = runResolve(os.Args[2:])
	case "-h", "--help", "help":
		fmt.Print(usage)
		return
	default:
		fmt.Fprintf(os.Stderr, "rig-helper: unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
	if err != nil {
		var ec exitCode
		if asExit(err, &ec) {
			os.Exit(int(ec))
		}
		fmt.Fprintf(os.Stderr, "rig-helper %s: %v\n", os.Args[1], err)
		os.Exit(1)
	}
}

// exitCode lets a subcommand propagate a child's exit status.
type exitCode int

func (e exitCode) Error() string { return fmt.Sprintf("exit status %d", int(e)) }

func asExit(err error, target *exitCode) bool {
	ec, ok := err.(exitCode)
	if ok {
		*target = ec
	}
	return ok
}
