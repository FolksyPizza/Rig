# Rig

Run AI coding agents in locked-down sandboxes.

Rig builds a container with your agent already installed, runs it as an
unprivileged user, and puts a default-deny network filter in front of it: the
agent can reach its own model API and the sites you list, and nothing else.
Everything it does on the network, through MCP tools and in its process table
is watched and recorded, and a sandbox that tries to send data somewhere it
shouldn't is stopped.

```bash
rig new work          # create a sandbox: Claude Code, standard security
rig run work          # build it if needed and open a shell inside
rig check work        # see exactly what it can and cannot reach
```

## Why

Coding agents run commands on your behalf, and the model behind one can be
wrong, manipulated by something it read, or simply not what it claims to be.
Cohere [reported](https://cohere.com/blog/concerning-behaviour-popular-open-weight-ai-model)
an open-weight model that, during an evaluation, inventoried the machine it
ran on and tried to upload a file to a cloud storage bucket, while its visible
reasoning said it would not call any tools. Their sandbox blocked it. Their
advice: deny network egress by default, enforce policy where tools are called,
and treat model weights like unsigned software.

Rig does all three. The sandbox can only reach an allowlist, known
exfiltration services are blocked even when allowlisted, MCP tool calls pass
through a policy guard, and the strictest levels add a gVisor or VM boundary
and stop the sandbox at the first attempt to break a rule.

## Install

You need Go 1.25 or later to build, and Docker or Podman to run sandboxes.

```bash
git clone https://github.com/FolksyPizza/Rig.git
cd Rig
make user-install      # installs ~/.local/bin/rig
rig doctor             # checks your engine and isolation runtimes
```

- **Linux**: Docker or Podman. For the strict and lockdown levels, install
  [gVisor](https://gvisor.dev/docs/user_guide/install/) or
  [Kata Containers](https://katacontainers.io/docs/); `rig doctor` tells you
  what is missing.
- **macOS**: Docker Desktop or Podman. Apple's `container` runtime works for
  open-level sandboxes (it runs each container in its own VM but cannot yet
  enforce the network filter); Rig switches to Docker or Podman for the other
  levels automatically when both are installed.
- **Windows**: use WSL2 with Docker.

Run `rig doctor --deep` once after installing. It starts throwaway containers
to confirm, on your machine, that a sandbox cannot look up outside names,
connect to services on your computer, or reach the cloud metadata address.

## Quick start

```bash
export ANTHROPIC_API_KEY=sk-ant-...   # or sign in inside the sandbox
rig new work --mount ~/code/project:/home/sandbox/project:rw
rig run work
```

Inside, run `claude` (or whichever agent you chose). Leave with `exit`. A
persistent sandbox is stopped when you leave, with its files kept, so nothing
runs in it unwatched; `rig run work` picks up where you left off.

API keys are written in profiles as `${VAR}` references and resolved from
your environment at launch. Claude Code can also sign in with your Claude
account from inside the sandbox (open the link it prints, then paste the code
back); a persistent sandbox keeps the login.

Pick another agent, level or template:

```bash
rig new work --agent codex --level strict
rig new api --agent opencode --allow docs.example.com --preset go
rig new safe --from lockdown
rig templates
```

## Security levels

A level sets defaults and a floor. A profile can be stricter than its level,
never looser: asking for sudo at strict, or an unrestricted network at
standard, is refused.

| | open | standard (default) | strict | lockdown |
|---|---|---|---|---|
| Network | anything allowed | allowlist | allowlist, HTTPS only | allowlist, HTTPS only |
| Exfiltration sites (paste, upload, tunnel, IP lookup) | blocked by default | blocked | blocked | blocked |
| Image | writable | writable | read-only, `/tmp` cannot run programs | read-only, `/tmp` and home cannot run programs |
| sudo | allowed | allowed | no | no |
| Isolation | strongest installed | strongest installed | prefers gVisor or VM | requires gVisor or VM |
| Monitoring | observe | stops clear attacks | stops after 3 blocked connections a minute | stops at the first blocked connection |
| Upload limit per connection | none | none | 256 MB | 64 MB |
| Agents | as installed | telemetry and auto-update off | npm install scripts off | web tools and permission bypass off; pip wheels only; programs from outside the image stop the sandbox |
| Lifetime | any | any | any | ephemeral only |

`rig levels` prints a summary. Every level runs the agent as user `sandbox`
(uid 1000) under the engine's seccomp filter, with CPU, memory and process
limits. Without sudo (never allowed at strict and lockdown) it also has no
Linux capabilities and cannot gain privileges (`no-new-privileges`); with
sudo it gets the few capabilities package managers need.

## Isolation: container, gVisor or VM

`security.isolation` chooses the boundary between the agent and your machine:

- `container`: the engine's normal runtime, hardened by Rig. The agent shares
  your machine's kernel, so a kernel bug can be an escape route.
- `gvisor`: gVisor's `runsc`, a user-space kernel. The agent's system calls
  never reach your kernel directly.
- `vm`: a lightweight virtual machine per sandbox (Kata Containers on Linux;
  Apple's runtime on macOS always works this way).
- `auto` (default): the strongest one installed. At lockdown, a sandbox will
  not start without gVisor or a VM.

## What a sandbox can reach

### The internet

In `allowlist` mode the sandbox's only network has no route out. Its one
neighbor is Rig's egress proxy, which is the only way out and checks every
connection:

- the destination must be on the allowlist (`*.example.com` includes
  subdomains);
- for HTTPS, the TLS server name must match the requested host, so an allowed
  name cannot front for another site;
- names are resolved by the proxy, and private, loopback, link-local and cloud
  metadata addresses are refused, so an allowed name cannot point inside your
  network;
- known upload, paste, tunnel and IP-lookup services are refused even if
  allowlisted, unless you name the exact host under `network.allow_risky`.

The allowlist is built from each agent's own API (with sign-in hosts), the
model APIs implied by the keys you configure, presets (`rig presets`: github,
npm, pypi, go, rust, huggingface, ubuntu, model providers), your own domains,
and the hosts of remote MCP servers. `rig allow work docs.python.org` adds one;
`rig check work` lists them all. `network.mode: none` removes the network
entirely.

### Your computer

Nothing on your computer is reachable from a sandbox by default. To let it use
a local service, such as Ollama, list the port:

```bash
rig new local --from local-model             # Qwen Code on your Ollama, no internet
rig new work --port ollama:11434             # rig-gw:11434 inside reaches 127.0.0.1:11434
```

The connection is relayed by the `rig` process through a gateway container.
Only the listed ports are relayed, and each connection is recorded.

### MCP servers and connected apps

MCP servers are listed in the profile, and Rig writes each agent's MCP
configuration for you (Claude Code, Codex, Gemini CLI, Qwen Code, OpenCode,
Crush). Every tool call goes through Rig's guard: tools you deny are hidden
from the agent and refused if called, and every call is recorded.

```yaml
mcp:
  servers:
    - name: blender
      command: [blender-mcp]
      packages: {pip: [blender-mcp]}
      run_in: gateway            # runs outside the sandbox
      host_ports: [9876]         # only this server can reach Blender
      deny_tools: [execute_blender_code]
```

Where a server runs matters:

- `run_in: gateway` runs the server in a separate container outside the
  sandbox. The agent can reach it only through the guard, which makes the
  guard a real boundary. Use it for anything that touches your computer or
  holds credentials (Blender, desktop apps, accounts). Its own network access
  is a separate allowlist (`domains:`).
- in the sandbox (the default), the server runs with the agent's privileges.
  The guard filters what the agent asks for over MCP, but an agent with a
  shell could run the server's code directly.
- a remote server (`url:`) is reached through the egress proxy. Rig sees the
  connection but not the tool calls, so tool rules cannot be applied, and
  lockdown does not allow remote servers.

The `blender` template sets this up, with Blender's arbitrary-code tool
blocked.

### Git repositories

Instead of handing the agent a token, give Rig the token and a list of
repositories:

```yaml
git:
  token_env: GITHUB_TOKEN          # read on your machine, kept in the gateway
  repos:
    - repo: you/project
      access: write
      branches: ["rig/*"]          # pushes allowed only to these branches
    - repo: you/docs               # read-only
```

Git inside the sandbox is pointed at Rig's git broker. The broker adds the
token on the way out and allows only the listed repositories, read or write as
configured, pushing only to matching branches. The token never enters the
sandbox.

### Files

Mount project folders with `--mount SRC:DST[:rw]` (read-only unless `:rw`).
Rig refuses to mount your home directory, credential folders (`~/.ssh`,
`~/.aws`, `~/.config/gh`, agent sign-in folders and others), the engine's
socket and system paths, and resolves symlinks before checking. Within a
mount you can keep paths read-only (`protect`) or hide them (`hide`):

```yaml
mounts:
  - source: /home/you/code/project
    target: /home/sandbox/project
    readonly: false
    protect: [.github, scripts/deploy.sh]
    hide: [.env, secrets]
```

At strict and above, `.git/hooks`, `.git/config`, `.github`, `.gitlab-ci.yml`,
`.circleci` and `.husky` are protected automatically in writable mounts: those
are where an agent would plant code that later runs outside the sandbox.

## Monitoring

While a sandbox runs, Rig watches the proxy's log, the gateway, the MCP guard,
the process table and resource use. Each event gets a severity, and the
level's policy decides whether it is recorded, flagged in your terminal, or
stops the sandbox. Attempts to reach exfiltration services, scanning and
tunnelling tools, and running programs from scratch directories are treated as
serious at every level.

```bash
rig audit work                 # what happened: connections, tool calls, processes
rig audit work --flagged       # only what Rig flagged or stopped
rig audit work -f              # follow new events
rig monitor work               # live view of a running sandbox
rig ps                         # shows whether each running sandbox is monitored
```

The audit log is kept on your machine (`rig audit work --path`), outside every
sandbox, so nothing inside can change it. Monitoring runs inside the `rig`
process that started the sandbox. For a sandbox left running with
`--keep-running`, `rig monitor` takes over.

### AI monitor

A second model can review what the sandbox does and raise alarms:

```yaml
monitor:
  ai:
    provider: anthropic            # anthropic, openai, or ollama for a local model
    model: claude-opus-5-5         # the default for anthropic
    enforce: false                 # true lets its verdicts stop the sandbox
```

or `rig new work --ai-monitor anthropic`. The AI monitor can only make Rig
stricter, never relax a rule. Secrets are redacted before review, and sandbox
output is framed so that text inside it cannot pose as instructions to the
reviewer. Its verdicts are advisory unless `enforce` is set; at lockdown they
are enforced.

## Agents

| ID | Agent | Keys |
|---|---|---|
| `claude-code` | Claude Code | `ANTHROPIC_API_KEY` or account sign-in |
| `codex` | Codex | `OPENAI_API_KEY` |
| `gemini-cli` | Gemini CLI | `GEMINI_API_KEY` |
| `pi` | Pi | Anthropic, OpenAI or Gemini keys |
| `opencode` | OpenCode | Anthropic or OpenAI keys |
| `qwen-code` | Qwen Code | any OpenAI-compatible endpoint |
| `crush` | Crush | Anthropic or OpenAI keys |
| `aider` | Aider | Anthropic or OpenAI keys |
| `copilot` | GitHub Copilot CLI | `GH_TOKEN` |
| `grove` | [Grove](https://github.com/FolksyPizza/grove) | OpenAI or Anthropic keys |
| `grok-build` | Grok Build | `XAI_API_KEY` |
| `openclaw` | OpenClaw | |
| `hermes` | Hermes Agent | |

Pin a version with `--agent claude-code@2.1.0`. Several agents can share one
sandbox (`--agent claude-code --agent codex`). Agents that work with many
providers get the domains of the keys you configure, and a `*_BASE_URL`
pointing at another provider or a local model is followed automatically.

To add your own, put a definition in `~/.config/rig/agents/<id>.yaml` (`rig
agents` prints the path). These files hold commands that run as root during
the image build, so they are local configuration only: a shared profile can
name a custom agent but never define one.

```yaml
id: mytool
name: My Tool
install:
  - npm install -g my-tool@1.2.3
node: "22"
command: my-tool
domains: [api.mytool.example]
env: [MYTOOL_API_KEY]
```

## Templates

`rig templates` lists them; `rig new <name> --from <template>` uses one.

| Template | |
|---|---|
| `standard` | Claude Code with an egress allowlist (the default) |
| `claude-strict` | Read-only image, HTTPS only, ephemeral |
| `lockdown` | Model API only, gVisor or VM required, ephemeral |
| `claude-dev` | Open level: unrestricted network and sudo, for trusted work |
| `codex`, `gemini`, `pi`, `opencode`, `qwen-code`, `grove` | Other agents with an allowlist |
| `local-model` | Qwen Code on your local Ollama, no internet at all |
| `blender` | Claude Code with Blender over MCP, code execution blocked |
| `multi-agent` | Claude Code, Gemini CLI and Codex side by side |
| `airgapped` | No network |
| `minimal` | Small and ephemeral |
| `hermes-research` | Hermes Agent with open web access (open level) |

## Commands

```text
Getting started
  rig new <name>            create a sandbox (--agent, --level, --from, --mount, --allow, --port, --sudo, ...)
  rig run <name>            start it and open a shell; 'rig run <name> -- <cmd>' runs a command
  rig templates             ready-made setups
  rig agents                installable agents
  rig levels                the security levels

Security
  rig check <name>          what it can and cannot do, with risks ranked
  rig doctor [--deep]       check this computer's engine, runtimes and isolation
  rig monitor <name>        watch a running sandbox live
  rig audit <name>          what a sandbox did

Configure
  rig edit <name>           edit the YAML in $EDITOR (validated on save)
  rig allow <name> <domain> allow a domain (--remove to undo)
  rig add <name> <pkg>      install apt packages (--npm, --pip) on the next run
  rig show <name>           print the settings (--dockerfile for the image recipe)
  rig presets               named groups of domains
  rig export / rig import   share a sandbox as YAML (imports are treated as untrusted)
  rig list                  saved sandboxes

Manage
  rig ps                    containers, and whether each is monitored
  rig shell <name>          another shell in a sandbox
  rig exec <name> -- <cmd>  run a command in a sandbox
  rig stop <name>           stop it, keeping its files
  rig rm <name>             remove its containers (--volumes, --all to delete everything)
  rig build <name>          build the image ahead of time (--no-cache for fresh agents)
  rig logs, cp, stats, top, diff, pause, unpause, commit, rename
```

`rig help <command>` explains each one. Every command that takes a sandbox
also accepts a container name from `rig ps`, such as `rig-work-2`.

## Profiles

Sandboxes are saved as YAML in `~/.config/rig/profiles/`. `rig new` writes
one for you; `rig edit` opens it. A fuller example:

```yaml
version: 1
name: work
security:
  level: strict                 # open | standard | strict | lockdown
  isolation: auto               # auto | container | gvisor | vm
agents:
  - id: claude-code
    env:
      ANTHROPIC_API_KEY: ${ANTHROPIC_API_KEY}   # resolved at launch, never stored
tools: [git, ripgrep, python3, make]            # apt packages
packages:
  npm: [typescript]
  pip: [pytest]
network:
  mode: allowlist               # allowlist | none | unrestricted (open level only)
  presets: [github, npm, pypi]
  allowed_domains: [docs.python.org, "*.readthedocs.io"]
host:
  ports:
    - {name: ollama, port: 11434}
git:
  token_env: GITHUB_TOKEN
  repos:
    - {repo: you/project, access: write, branches: ["rig/*"]}
mcp:
  servers:
    - name: docs
      command: [npx, -y, some-docs-mcp]
      allow_tools: [search, read_page]
monitor:
  mode: enforce                 # off | observe | enforce
  strictness: high              # low | medium | high
mounts:
  - {source: /home/you/code/project, target: /home/sandbox/project, readonly: false}
resources: {cpu: 2, memory: 4096, pids_limit: 512}
storage:
  size: 10g
  volumes:
    - {name: workspace, target: /home/sandbox/workspace}
persistence: persistent         # persistent | ephemeral
```

### Environment variables

| Variable | |
|---|---|
| `RIG_ENGINE` | force `docker`, `podman` or `apple` |
| `RIG_BASE_IMAGE` | base image instead of `ubuntu:24.04` (a mirror, or a digest pin) |
| `RIG_NODE_IMAGE` | image Node.js is copied from, instead of `node:<major>-bookworm-slim` |
| `RIG_GO_IMAGE` | image that builds Rig's helper, instead of `golang:1.25-alpine` |
| `RIG_AGENTS_DIR` | where custom agent definitions live |

## Limits

Rig narrows what an agent can do and records what it tries. Some things are
outside what it can promise:

- **A shell can run code.** Even at lockdown, an agent with a shell can run
  interpreted code inside the sandbox. Lockdown stops programs the agent
  builds or downloads from running, keeps install scripts off, and limits
  where anything can connect, but containment comes from the isolation
  boundary and the network filter, not from preventing execution.
- **Process monitoring samples.** The process table is polled every two
  seconds, so a very short-lived process can be missed. The egress proxy sees
  every connection.
- **In-sandbox MCP servers run with the agent's privileges.** Run anything
  sensitive in the gateway. Audit lines from an in-sandbox guard come from
  inside the sandbox; the gateway's and the proxy's do not.
- **Allowed sites are allowed.** If a site on the allowlist accepts uploads
  (for example a code host the agent can push to), data can leave through it.
  Keep allowlists short, scope git access with the broker, and prefer presets
  over wildcards.
- **Container isolation shares your kernel.** Use gVisor or a VM for code you
  do not trust; lockdown requires one.
- **Image builds have network access.** Packages and agents are installed
  from their registries when the image is built; the filter applies when the
  sandbox runs. Grok Build and Hermes Agent install through their vendors'
  install scripts.
- **The engine stores the sandbox's environment.** API keys passed to a
  sandbox are kept in its container configuration while the container exists
  (`rig commit` blanks them in snapshots). Use the git broker and gateway MCP
  servers to keep credentials out of the sandbox altogether.
- **Mounts you add are trusted.** Rig blocks the dangerous ones, but a folder
  you mount read-write can be changed by the agent.
- **GPU passthrough is not available yet.** A profile asking for it is
  refused rather than silently ignored.

See [SECURITY.md](SECURITY.md) for the threat model and how to report a
vulnerability.

## Development

```bash
make build                            # bin/rig
make check                            # go vet and go test
go test -race ./...
scripts/integration-test.sh bin/rig   # end-to-end checks against your container engine
```

The integration tests build real sandboxes and check from inside them what each level promises. CI runs them on
Docker with gVisor installed; set `RIG_IT_SKIP=gvisor` (or `internet`, `claude`) for what your machine lacks.

`rig-helper` (the egress proxy, gateway and MCP guard) is built from this
repository inside the image build and uses only Go's standard library; a test
enforces that.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
Copyright 2026 William W. (FolksyPizza). Versions before the license change
were published under the MIT License.
