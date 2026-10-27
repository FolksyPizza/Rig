// Package rig embeds the source of rig-helper, the small program Rig runs
// inside containers as the egress proxy, MCP gateway and tool-call guard.
//
// The rig binary may be built for macOS or Windows, but the helper must run
// on Linux inside the container engine. Rather than ship prebuilt binaries,
// Rig hands this source to a Go builder stage in an image build, so the
// helper always matches the rig version that launched it. Everything here
// must therefore depend on the Go standard library only; helpersrc_test.go
// enforces that.
package rig

import "embed"

// HelperSource holds the helper's packages, laid out as in this repository.
//
//go:embed cmd/rig-helper/*.go internal/egress/*.go internal/mcpguard/*.go internal/relay/*.go internal/gitbroker/*.go internal/gateway/*.go
var HelperSource embed.FS

// HelperPackages are the directories embedded in HelperSource.
var HelperPackages = []string{
	"cmd/rig-helper",
	"internal/egress",
	"internal/mcpguard",
	"internal/relay",
	"internal/gitbroker",
	"internal/gateway",
}

// ModulePath is the module the embedded packages import each other through.
const ModulePath = "github.com/FolksyPizza/rig"
