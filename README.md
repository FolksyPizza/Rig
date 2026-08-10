# Rig

Containerized sandboxes for AI coding agents. Rig builds an isolated Docker
environment with the agent already installed, drops it to an unprivileged user
with no Linux capabilities, and — when you ask for it — puts a real egress
allowlist in front of its network. Configure it through a terminal wizard or
the CLI.

```bash
rig template use claude-secure my-sandbox
rig run my-sandbox
```

## Why

Coding agents run shell commands on your machine. Rig gives them somewhere else
to run: a container that can't see your home directory, can't escalate
privileges, and can only reach the domains you listed.

## Install

Requires Go 1.25+ to build and Docker to run.

```bash
git clone https://github.com/FolksyPizza/Rig.git
cd Rig
make user-install    # installs to ~/.local/bin/rig
# or
make install         # installs to /usr/local/bin/rig (uses sudo)
```

## Quick start

```bash
rig                             # interactive wizard
rig template list               # or start from a template
rig template use claude-dev dev
rig run dev
```

Set the agent's API key on your host before launching; Rig passes `${VAR}`
references through to the sandbox without ever writing the value to disk.

```bash
export ANTHROPIC_API_KEY=sk-...
rig run dev
```

## Supported agents

| ID | Agent | Env var |
|----|-------|---------|
| `claude-code` | Claude Code | `ANTHROPIC_API_KEY` |
| `codex` | Codex | `OPENAI_API_KEY` |
| `grok-build` | Grok Build | `XAI_API_KEY` |
| `gemini-cli` | Gemini CLI | `GEMINI_API_KEY` |
| `openclaw` | OpenClaw | — |
| `hermes` | Hermes Agent | — |

`rig agents` prints this list.

## Security model

This section describes what Rig actually enforces, and what it does not.

### What is enforced

**No capabilities.** Containers run with `--cap-drop ALL`. Verified inside a
running sandbox: `CapEff: 0000000000000000`.

**No privilege escalation.** `--security-opt no-new-privileges` is set
(`NoNewPrivs: 1`), and the image ships **no `sudo`** at all. The agent runs as
the unprivileged `sandbox` user and has no path to root.

**Default seccomp.** Rig deliberately does *not* install a custom seccomp
profile. Docker's default profile is a strict allowlist that already blocks
`kexec_load`, `init_module`, `mount`, `reboot`, `bpf` and friends. Replacing it
with a hand-written allow-by-default profile would *weaken* confinement, which
is exactly what an earlier version of this tool did.

**Resource limits.** CPU, memory, and PID limits via cgroups. Memory and
memory-swap are pinned to the same value, so the memory cap cannot be sidestepped
through swap. `pids_limit` is required to be at least 16 — Docker treats 0 and
-1 as *unlimited*, which would silently remove fork-bomb protection.

**Egress allowlist (`network.mode: allowlist`).** This is a network boundary,
not an environment variable:

```
sandbox ── rig-net-<profile> (--internal, no route off-host) ── squid proxy
                                                                    │
                                            rig-egress-<profile> ── internet
```

The sandbox's only network is marked `--internal`, so it has no route anywhere
except the proxy. The proxy is dual-homed and is the sole path out. Setting
`HTTP_PROXY` alone would accomplish nothing — any process can ignore the
variable and open a socket directly.

Measured from inside a running sandbox with `example.com` allowlisted:

| Attempt | Result |
|---|---|
| Raw TCP to `1.1.1.1:80` | Network unreachable |
| `curl` with proxy vars unset | blocked |
| DNS query to `8.8.8.8` | Network unreachable |
| `http://example.com` (allowed) | HTTP 200 |
| `http://google.com` (not allowed) | HTTP 403 |
| `https://google.com` (not allowed) | blocked at CONNECT |

**Fail-closed.** If the allowlist network or proxy cannot be brought up, Rig
refuses to launch rather than falling back to the default bridge. A profile
that asks for an allowlist never silently gets unrestricted internet.

**Untrusted profiles.** Profiles are shareable YAML files, so `rig import`
treats them as hostile input. Rejected: names that traverse out of the profile
directory, host mounts of the Docker socket or `/proc`, `/sys`, `/dev`, `/etc`
and similar, allowlist domains containing control characters (which would
inject directives into the generated `squid.conf`), tool names containing
newlines (which would append instructions to the generated Dockerfile), and
unlimited PID limits.

**Secrets stay off the process table.** Resolved API keys are passed with
`--env-file` from a 0600 file, not as `-e KEY=value` arguments where any local
user running `ps` could read them. Profile files are written 0600.

### What is not enforced

- **`commands.mode: allowlist` is not a confinement boundary.** It filters
  `rig exec`, Rig's own entry point. An agent with an interactive shell inside
  the container can run anything the image contains. Use the network controls
  for real restriction.
- **Container escape is Docker's boundary, not Rig's.** Rig hardens a container;
  it does not add a VM. A kernel or runtime vulnerability defeats it. For
  hostile code rather than merely careless agents, use a VM.
- **Bind mounts you configure are trusted.** Rig blocks the paths that grant
  host control, but a mount you add is a real hole in the sandbox by design.
  Symlinks on the host side are not resolved.
- **The image build has network access.** Building installs packages from
  Ubuntu, NodeSource and npm; the allowlist applies at run time, not build time.
- **GPU passthrough is not implemented.** A profile with `gpu.enabled: true` is
  rejected rather than silently ignored.

## Commands

### Profiles

```bash
rig                             # launch the wizard
rig new                         # same thing
rig list                        # saved profiles
rig agents                      # supported agents
rig inspect <profile>           # show the generated Dockerfile
rig export <profile> [file]     # export for sharing (keeps ${VAR} refs)
rig import <file>               # import (validated as untrusted input)
rig delete <profile> --yes      # profile + image + containers + networks
```

### Templates

```bash
rig template list
rig template use <template> [name] [--force]
rig template inspect <template>
```

| Template | Description |
|---|---|
| `claude-dev` | Claude Code, full dev tools, unrestricted network |
| `claude-secure` | Claude Code with an egress allowlist |
| `codex-dev` | Codex with full dev tools |
| `multi-agent` | Claude Code + Gemini CLI + Codex together |
| `airgapped` | Fully offline, no network |
| `minimal` | Lightweight, minimal tools |
| `hermes-research` | Hermes Agent for research tasks |

### Running

```bash
rig run <profile>               # build if needed, then enter
rig run <profile> --new         # additional instance alongside existing ones
rig run <profile> --timeout 2h  # auto-stop after a duration
rig build <profile> [--no-cache]
```

By default `rig run` reuses an existing instance: a running one is re-entered, a
stopped one restarted. Instances are named `rig-<profile>`, `rig-<profile>-2`, …

### Interacting

```bash
rig shell <container>
rig exec <container> -- ls -la
rig logs <container> [-f] [-n 50]
rig cp <container>:/path ./local      # container -> host
rig cp ./local <container>:/path      # host -> container
```

### Managing

```bash
rig ps
rig stop <container> | rig stop <profile> --all
rig destroy <container> | rig destroy <profile> --all
rig pause <container> / rig unpause <container>
rig rename <container> <new-name>
rig commit <container> [tag]          # snapshot as an image
rig stats <container> / rig top <container> / rig diff <container>
```

Commands that take `--all` match on the `rig.profile` label, so
`rig destroy foo --all` cannot reach a sibling profile like `foo-extra`.

## Profile format

Profiles live in `~/.config/rig/profiles/` as YAML.

```yaml
version: 1
name: my-sandbox
agents:
  - id: claude-code
    env:
      ANTHROPIC_API_KEY: "${ANTHROPIC_API_KEY}"   # resolved at launch, never stored
tools: [git, ripgrep, neovim, tmux, python3]
network:
  mode: allowlist            # unrestricted | allowlist | none
  allowed_domains:
    - api.anthropic.com
    - "*.githubusercontent.com"   # "*." means "and subdomains"
commands:
  mode: unrestricted         # allowlist only guards `rig exec`
resources:
  cpu: 2.0
  memory: 4096               # MB
  pids_limit: 512            # must be >= 16
storage:
  size: 10g                  # ignored on storage drivers without quota support
  volumes:
    - name: workspace
      target: /home/sandbox/workspace
mounts:
  - source: /home/me/project # host path; escape-prone paths are refused
    target: /home/sandbox/project
    readonly: true
persistence: persistent      # persistent | ephemeral
```

`RIG_PROXY_IMAGE` overrides the Squid image used for allowlist mode.

## Development

```bash
make build
make fmt
make vet
go test ./...
go test -race ./...
```

## Roadmap

- GPU passthrough (NVIDIA and AMD)
- Audit logging for agent actions
- Workspace sync (bidirectional file watching)

## License

MIT — see [LICENSE](LICENSE).
