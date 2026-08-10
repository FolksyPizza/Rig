# Security Policy

## Reporting a vulnerability

Please report security issues privately through
[GitHub Security Advisories](https://github.com/FolksyPizza/Rig/security/advisories/new)
rather than opening a public issue.

## Threat model

Rig confines an AI coding agent that you are running deliberately but do not
fully trust to behave. It is a guardrail against a careless or misdirected
agent, not a containment boundary for deliberately hostile code.

### In scope

- Escaping the sandbox's egress allowlist.
- A shared profile (`rig import`) that reads or writes host files, mounts
  host-controlling paths, or injects directives into the generated
  `squid.conf` or Dockerfile.
- Leaking API keys passed into a sandbox to other users on the host.
- Commands that reach containers belonging to a different profile.
- Losing privilege restrictions (capabilities, `no-new-privileges`) or
  resource limits.

### Out of scope

- Container escape via a Docker or kernel vulnerability. Rig hardens a
  container; it does not add a virtualization boundary. Use a VM for hostile
  code.
- Anything reachable through a bind mount you configured. Mounts are a
  deliberate hole in the sandbox.
- Network access during image builds. Package installation needs the network;
  the allowlist applies at run time.
- `commands.mode: allowlist` failing to stop a process inside the container.
  It filters `rig exec` only, and says so in the docs.

## Hardening summary

Every sandbox runs with `--cap-drop ALL`, `--security-opt no-new-privileges`,
Docker's default seccomp profile, cgroup CPU/memory/PID limits, memory-swap
pinned to the memory limit, and an unprivileged `sandbox` user in an image that
contains no `sudo`. Allowlist mode places the sandbox on an `--internal`
network whose only route out is a filtering proxy, and refuses to launch if
that cannot be established.
