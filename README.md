# Rig

Run AI coding agents in locked-down sandboxes: Claude Code, Codex, Gemini
CLI, Pi, OpenCode, Qwen Code, Crush, Aider, Copilot, Grove and more, or your
own.

Rig builds a container with your agent already installed, runs it as an
unprivileged user, and puts a default-deny network filter in front of it: the
agent can reach its own model API and the sites you list, and nothing else.
Everything it does on the network, through MCP tools and in its process table
is watched and recorded, and a sandbox that tries to send data somewhere it
shouldn't is stopped.

```bash
rig new               # guided: pick the agent, security level, folder and resources
rig run work          # start it and open a shell (-d runs it in the background)
rig blocked work      # see what Rig blocked, and allow what you need
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

Rig needs Docker or Podman to run sandboxes.

**Without cloning** (Linux and macOS):

```bash
curl -fsSL https://raw.githubusercontent.com/FolksyPizza/Rig/main/install.sh | sh
rig doctor             # checks your engine and isolation runtimes
```

The script downloads the latest release for your computer, checks it against
the release's `SHA256SUMS` and installs it in `~/.local/bin`. If no release
build is available it builds Rig from source (needs git and Go 1.25+).
`RIG_VERSION=v0.3.0` picks a release, `RIG_INSTALL_DIR=/usr/local/bin` another
location. Read the script first if you prefer: it is short.

**From a clone** (needs Go 1.25+):

```bash
git clone https://github.com/FolksyPizza/Rig.git
cd Rig
make user-install      # installs ~/.local/bin/rig
rig doctor
```

**Updating:** `rig update` installs the latest release in place (checksum
verified; `rig update --check` only looks). From a clone, `git pull && make
user-install`. `rig update work` rebuilds a sandbox with the latest versions
of its agents.

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
export OPENAI_API_KEY=...        # or ANTHROPIC_API_KEY, GEMINI_API_KEY, ...; or sign in inside
cd ~/code/project
rig new
```

`rig new` asks a few questions, each with a default (press Enter to accept):
which agent, the security level, whether to share the current folder, what
the agent may do without asking you, CPU, memory and disk, extra sites to
allow, sudo, and whether to keep files between runs. Then it offers to start
the sandbox. Inside, run your agent (`codex`, `claude`, `gemini`, ...); leave
with `exit`.

The same with flags, for scripts:

```bash
rig new work --agent codex --mount .:/home/sandbox/project:rw
rig new work --agent claude-code --level strict --cpu 4 --memory 8g --disk 20g
rig new work --agent gemini-cli --permissions full     # no approval prompts inside
rig new safe --from lockdown --agent opencode
```

Without `--agent`, Rig uses the agent whose API key it finds. API keys are
written in profiles as `${VAR}` references and resolved from your
environment at launch, never stored. Claude Code and Codex can also sign in
with your account from inside the sandbox; a persistent sandbox keeps the
login.

### Day to day

```bash
rig run work                  # start it and open a shell; leaving stops it (files kept)
rig run work -d               # run it in the background, still monitored
rig shell work                # enter a running sandbox (another terminal, or after -d)
rig stop work                 # stop it
rig set work cpu=4 memory=8g  # change settings ('rig set work' lists them all)
rig blocked work              # sites Rig refused; pick which to allow
rig allow work docs.rs        # allow a site; a running sandbox gets it at once
rig update work               # newest agent versions
```

When Rig blocks a connection it prints one line naming the site and the
command that would allow it, and your shell or agent carries on: there is no
need to press Ctrl-C. When you leave, Rig lists what it blocked during the
session. If Rig stops a sandbox for a serious violation, an interactive
session offers to restart it, show what happened, or (for an ordinary block)
allow the site and restart.

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
| Agent permissions | any | any | any | ask or edit (no `full`) |
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
rig blocked work               # sites refused for not being on the allowlist
rig ps                         # shows how each running sandbox is monitored
```

The audit log is kept on your machine (`rig audit work --path`), outside every
sandbox, so nothing inside can change it. Monitoring runs in a Rig process:
the one that opened your session, or, for a sandbox started with `rig run -d`
(or left with `--keep-running`), a background Rig process that also owns the
sandbox's gateway. Nothing runs in a sandbox unwatched: stopping the
background process stops the sandbox, and `rig stop` ends both.

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
| `codex` | Codex | `OPENAI_API_KEY` or ChatGPT sign-in |
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

### What agents may do without asking

`--permissions` (or `rig set work permissions=...`, or
`security.agent_permissions`) sets how much the agents ask you first:

| Mode | Meaning |
|---|---|
| `ask` (default) | each agent's own default: it asks before acting |
| `edit` | file edits without asking; it still asks before running commands |
| `full` | no approval prompts; the sandbox is the boundary (not allowed at lockdown) |

Rig applies each agent's own documented setting: Claude Code
`--permission-mode acceptEdits` / `bypassPermissions`; Codex
`--ask-for-approval untrusted` / `--dangerously-bypass-approvals-and-sandbox`
(Codex's own command sandbox cannot run inside a container, so Rig's is the
boundary); Gemini CLI and Qwen Code `--approval-mode` / `--yolo`; Crush
`--yolo`; Aider `--yes-always`; Copilot `--allow-tool write` /
`--allow-all-tools`; OpenCode through its config file. Pi never asks. The
flags are added by a small wrapper in `/etc/rig/bin`, read-only to the agent.
`rig check` reports the mode.

### Your own agents

Put a definition in `~/.config/rig/agents/<id>.yaml` (`rig agents` prints the
path). These files hold commands that run as root during the image build, so
they are local configuration only: a shared profile can name a custom agent
but never define one.

```yaml
id: mytool
name: My Tool
install:
  - npm install -g my-tool@1.2.3
node: "22"
command: my-tool
domains: [api.mytool.example]
env: [MYTOOL_API_KEY]
permissions:                 # optional: flags for Rig's permission modes
  edit: [--auto-edit]
  full: [--yolo]
```

## Templates

`rig templates` lists them; `rig new <name> --from <template> --agent <id>`
uses one. Most work with any agent.

| Template | |
|---|---|
| `standard` | Egress allowlist, exfiltration sites blocked (the default) |
| `strict` | Read-only image, HTTPS only, no sudo, ephemeral |
| `lockdown` | Model API only, gVisor or VM required, ephemeral |
| `dev` | Open level: unrestricted network, sudo, no approval prompts, for trusted work |
| `airgapped` | No network |
| `minimal` | Small and ephemeral |
| `blender` | Blender over MCP, its code-execution tool blocked |
| `local-model` | Qwen Code on your local Ollama, no internet at all |
| `multi-agent` | Claude Code, Codex and Gemini CLI side by side |
| `hermes-research` | Hermes Agent with open web access (open level) |

The older agent-named templates (`codex`, `gemini`, `pi`, `opencode`,
`qwen-code`, `grove`, `claude-strict`, `claude-dev`) still work: each is a
template above with that agent.

## Commands

`rig`, `rig help` and `rig --help` all show this list; `rig help <command>`
explains one command and its options.

```text
Use a sandbox
  rig new [name]              create one: guided in a terminal, or with flags
  rig run <name>              start it and open a shell (-d background, -- <cmd> run a command)
  rig shell <name>            enter a running sandbox
  rig exec <name> -- <cmd>    run a command in it
  rig stop <name>             stop it, keeping its files
  rig ps / rig list           running containers / saved sandboxes

Configure
  rig set <name> key=value    cpu, memory, disk, pids, level, permissions, network, timeout, ...
  rig allow <name> <domain>   allow a site (--remove to undo); applies to a running sandbox
  rig blocked <name>          sites Rig refused, and pick which to allow
  rig add <name> <pkg>        install apt packages (--npm, --pip)
  rig edit / rig show         the full YAML
  rig templates, agents, levels, presets, export, import

Watch and check
  rig check <name>            what it can and cannot do, with risks ranked
  rig monitor <name>          live view
  rig audit <name>            what it did
  rig doctor [--deep]         this computer's engine, runtimes and isolation

Manage
  rig update [name]           update Rig itself, or a sandbox's agents
  rig rm <name>               remove its containers (--all deletes everything)
  rig build, logs, cp, stats, top, diff, pause, unpause, commit, rename, version
```

Every command that takes a sandbox also accepts a container name from
`rig ps`, such as `rig-work-2`.

## Profiles

Sandboxes are saved as YAML in `~/.config/rig/profiles/`. `rig new` writes
one for you; `rig edit` opens it. A fuller example:

```yaml
version: 1
name: work
security:
  level: strict                 # open | standard | strict | lockdown
  isolation: auto               # auto | container | gvisor | vm
  agent_permissions: edit       # ask | edit | full
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
metadata:
  timeout: 2h                   # stop automatically after this long
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
