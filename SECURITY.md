# Security Policy

## Reporting a vulnerability

Please report security issues privately through
[GitHub Security Advisories](https://github.com/FolksyPizza/Rig/security/advisories/new)
rather than opening a public issue. Include the Rig version (`rig version`),
your container engine and version (`rig doctor`), and the profile involved if
there is one (`rig export` keeps secrets out of it).

You should get a first response within a week. Fixes for confirmed issues are
released as soon as they are ready, and the advisory credits the reporter
unless you ask otherwise.

## Threat model

Rig runs an AI coding agent that you start deliberately but do not trust to
behave: the model may be mistaken, manipulated by content it reads, or
deliberately hostile. Rig's job is to limit what the agent can reach, to
record what it does, and to stop it when it tries something the sandbox's
security level forbids.

### Boundaries

- **Network.** In allowlist mode the sandbox's only network has no route out
  and no address for your computer (Docker); the egress proxy, running in a
  separate minimal container, is the only path out. The proxy enforces the
  allowlist, checks that the TLS server name matches the requested host,
  resolves names itself and refuses private, loopback, link-local and
  metadata addresses, and refuses known exfiltration services.
- **Gateway.** MCP servers marked `run_in: gateway`, the git broker and host
  port relays run in a separate container. The sandbox can reach them only
  over HTTP through Rig's guard; tokens given to the gateway never enter the
  sandbox.
- **Isolation.** A hardened container (no capabilities, `no-new-privileges`,
  seccomp, resource limits, unprivileged user), optionally on gVisor or in a
  VM. Lockdown refuses to run without gVisor or a VM.
- **Configuration.** Shared profiles (`rig import`) are untrusted input: every
  field is validated, dangerous mounts are refused, and a profile can name but
  never define a custom agent.

### In scope

- Reaching a destination the effective allowlist does not permit, including
  through DNS, other protocols, address tricks or the TLS server name.
- Reaching a service on the host or the local network from a sandbox, other
  than the host ports the profile lists.
- Getting the git broker to read or write a repository, or push to a branch,
  that the profile does not allow, or obtaining its token from the sandbox.
- Calling an MCP tool that the guard should refuse on a gateway server, or
  obtaining credentials held by the gateway.
- A profile accepted by `rig import` or `rig edit` that weakens the level's
  floor, mounts a forbidden path, or injects into a generated Dockerfile,
  proxy configuration or agent configuration.
- Making a sandbox's activity invisible to the proxy's, gateway's or monitor's
  records on the host, or changing those records from inside a sandbox.
- Losing privilege restrictions or resource limits, or reaching another
  profile's containers through Rig's commands.
- Leaking secrets passed to a sandbox to other local users or into images.

### Out of scope

- Escaping a plain container through a kernel or engine vulnerability. Use
  gVisor or a VM; lockdown requires one. Escapes from gVisor or Kata are their
  projects' issues, though we want to hear about them.
- What an agent does with destinations you allowlisted, or with folders you
  mounted read-write.
- Code running inside the sandbox: an agent with a shell can run interpreted
  code there. Rig limits what that code can reach and records what it does.
- In-sandbox MCP servers bypassed by the agent running their code directly.
  These run with the agent's privileges by design; the documentation says to
  use the gateway for anything sensitive.
- Network access during image builds, and the integrity of the registries and
  installers agents are installed from.
- `commands.mode: allowlist` failing to stop processes inside the container;
  it guards `rig exec` only, and says so.

## Hardening summary

Every sandbox runs as uid 1000 with `--cap-drop ALL`, `no-new-privileges`,
the engine's default seccomp profile, and CPU, memory (swap pinned) and PID
limits; with the optional sudo (open and standard levels only) it gets the
handful of capabilities package managers need instead. At strict and above
the image is read-only, `/tmp` is mounted `noexec`, HTTPS is required, and
paths such as `.git/hooks` and `.github` in writable mounts are read-only. At
lockdown the sandbox is ephemeral, home is `noexec`, gVisor or a VM is
required, MCP servers must run in the gateway with explicit tool lists, and
the first blocked connection stops the sandbox. API keys reach a sandbox
through a private env file that is deleted right after the container is
created, never through command-line arguments, and are blanked in
`rig commit` snapshots. The audit log lives on the host with mode 0600.
