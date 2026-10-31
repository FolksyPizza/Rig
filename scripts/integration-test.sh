#!/usr/bin/env bash
# End-to-end checks of Rig against a real container engine. It creates
# sandboxes in a scratch home, then confirms from inside them what each
# security level promises. CI runs it on Docker with gVisor installed; run it
# locally the same way:
#
#   go build -o bin/rig ./cmd/rig && scripts/integration-test.sh bin/rig
#
# RIG_IT_SKIP skips groups of checks, comma-separated:
#   internet  this machine cannot reach the internet directly
#   gvisor    no gVisor (runsc) runtime: lockdown is checked to refuse instead
#   claude    do not build the full Claude Code image
set -euo pipefail

[ $# -eq 1 ] || { echo "usage: $0 path/to/rig" >&2; exit 2; }
rig="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
skip=",${RIG_IT_SKIP:-},"
work="$(mktemp -d)"
port=47123

# Profiles, custom agents and audit logs live in a scratch home.
export HOME="$work/home"
mkdir -p "$HOME/.config/rig/agents" "$work/mcp" "$work/www"

passed=0
failed=0
skipping() { [[ "$skip" == *",$1,"* ]]; }
pass() { echo "PASS  $*"; passed=$((passed + 1)); }
fail() { echo "FAIL  $*"; failed=$((failed + 1)); }
show() { sed 's/^/      | /' "$work/out" | grep -v '^      | #' | tail -25; }

# expect <exit code> <description> <command...>
expect() {
	local want=$1 desc=$2 code=0
	shift 2
	"$@" </dev/null >"$work/out" 2>&1 || code=$?
	if [ "$code" = "$want" ]; then pass "$desc"; else fail "$desc (exit $code, want $want)"; show; fi
}

# expect_output <description> <extended regexp> <command...>: exit 0 and output matching.
expect_output() {
	local desc=$1 pattern=$2 code=0
	shift 2
	"$@" </dev/null >"$work/out" 2>&1 || code=$?
	if [ "$code" = 0 ] && grep -Eq -- "$pattern" "$work/out"; then pass "$desc"; else fail "$desc (exit $code)"; show; fi
}

cleanup() {
	for name in std tight safe bg quiet mcp gwmcp relay cc; do "$rig" rm "$name" --all --yes >/dev/null 2>&1 || true; done
	[ -n "${web_pid:-}" ] && kill "$web_pid" 2>/dev/null || true
}
trap cleanup EXIT

# A test agent that installs nothing, so most checks build quickly.
cat >"$HOME/.config/rig/agents/testagent.yaml" <<'EOF'
id: testagent
name: Test agent
description: Integration tests only
install:
  - "true"
command: bash
verify: bash --version
EOF
chmod 600 "$HOME/.config/rig/agents/testagent.yaml"

echo "== engine"
expect 0 "rig doctor --deep: sandbox networks cannot look up names, reach this computer or cloud metadata" "$rig" doctor --deep

echo "== standard level"
"$rig" new std --agent testagent --allow example.com >/dev/null
if skipping internet; then
	echo "skip  an allowed site is reachable (no internet here)"
else
	expect 0 "an allowed site is reachable through the egress proxy" "$rig" run std -- curl -fsS -o /dev/null --max-time 30 https://example.com
fi
expect 56 "a site off the allowlist is refused at the proxy" "$rig" run std -- curl -sS -o /dev/null --max-time 30 https://example.org
expect 6 "names do not resolve without the proxy" "$rig" run std -- curl -sS -o /dev/null --max-time 10 --noproxy '*' https://example.com
expect 7 "there is no route out without the proxy" "$rig" run std -- curl -sS -o /dev/null --max-time 10 --noproxy '*' http://1.1.1.1
expect_output "the agent runs unprivileged, with no capabilities" '^1000 CapEff:[[:space:]]+0+$' \
	"$rig" run std -- sh -c 'printf "%s " "$(id -u)"; grep CapEff /proc/self/status'
expect 3 "reaching for a paste site stops the sandbox" "$rig" run std -- sh -c 'curl -s -o /dev/null --max-time 10 https://pastebin.com; sleep 60'
expect_output "the audit log records why it was stopped" 'STOP +exfil_attempt' "$rig" audit std --flagged

echo "== strict level"
"$rig" new tight --agent testagent --level strict --allow example.com >/dev/null
# /var/tmp is writable by everyone in an ordinary image; at strict the whole image is read-only.
expect 0 "the image is read-only" "$rig" run tight -- sh -c 'touch /var/tmp/probe 2>&1 | grep -q "Read-only file system"'
expect 126 "/tmp cannot run programs" "$rig" run tight -- sh -c 'cp /bin/true /tmp/probe && /tmp/probe'
expect 22 "plain HTTP is refused, even to an allowed site" "$rig" run tight -- curl -fsS -o /dev/null --max-time 30 http://example.com

echo "== lockdown level"
"$rig" new safe --agent testagent --level lockdown --allow example.com >/dev/null
if skipping gvisor; then
	expect 1 "lockdown refuses to start without gVisor or a VM" "$rig" run safe -- true
else
	host_kernel="$(uname -r)"
	expect 0 "lockdown runs under gVisor, not the host kernel" "$rig" run safe -- sh -c "[ \"\$(uname -r)\" != \"$host_kernel\" ]"
	if skipping internet; then
		echo "skip  lockdown reaches an allowed site (no internet here)"
	else
		expect 0 "lockdown reaches an allowed site through the proxy" "$rig" run safe -- curl -fsS -o /dev/null --max-time 30 https://example.com
	fi
	expect 3 "lockdown stops at the first blocked connection" "$rig" run safe -- sh -c 'curl -s -o /dev/null --max-time 10 https://example.org; sleep 60'
	expect 3 "lockdown stops a program from outside the image" "$rig" run safe -- sh -c 'cp /bin/sleep ./probe && ./probe 60'
fi

echo "== background sandbox"
"$rig" new bg --agent testagent >/dev/null
expect 0 "a sandbox starts in the background" "$rig" run bg -d
expect_output "rig ps shows it monitored in the background" 'rig-bg .*yes \(background' "$rig" ps
expect 56 "a site off the allowlist is refused" "$rig" exec bg -- curl -sS -o /dev/null --max-time 30 https://example.org
expect_output "rig blocked lists the refused site" 'example\.org' "$rig" blocked bg
expect_output "rig allow applies to the running sandbox at once" 'running sandbox right away' "$rig" allow bg example.org
if skipping internet; then
	echo "skip  the newly allowed site is reachable (no internet here)"
else
	expect 0 "the newly allowed site is reachable without a restart" "$rig" exec bg -- curl -fsS -o /dev/null --max-time 30 https://example.org
fi
expect 3 "the background monitor stops it on an exfiltration attempt" "$rig" exec bg -- sh -c 'curl -s -o /dev/null --max-time 10 https://pastebin.com; sleep 60'
expect_output "the sandbox is stopped" 'rig-bg .*(Exited|exited)' "$rig" ps
expect 0 "it starts again in the background" "$rig" run bg -d
expect 0 "rig stop ends it" "$rig" stop bg
sleep 3
if pgrep -f "_supervise bg" >/dev/null; then fail "the background monitor exits with the sandbox"; else pass "the background monitor exits with the sandbox"; fi

"$rig" new quiet --agent testagent --monitor off >/dev/null
expect 0 "a background sandbox with monitoring off starts" "$rig" run quiet -d
sleep 5
expect_output "and keeps running" 'rig-quiet .*Up' "$rig" ps
expect 0 "rig stop ends it" "$rig" stop quiet

echo "== settings"
expect_output "rig set shows the settings" 'permissions +ask' "$rig" set bg
expect 0 "rig set changes compute and permissions" "$rig" set bg cpu=1.5 memory=1g permissions=full
expect_output "the agent's permission mode is saved" 'agent_permissions: full' "$rig" show bg
expect 1 "lockdown refuses full agent permissions" "$rig" set bg level=lockdown permissions=full

echo "== MCP guard"
cat >"$work/mcp/fake_mcp.py" <<'EOF'
import json, sys
TOOLS = [{"name": "echo", "inputSchema": {"type": "object"}}, {"name": "danger", "inputSchema": {"type": "object"}}]
for line in sys.stdin:
    msg = json.loads(line)
    if "id" not in msg:
        continue
    method = msg.get("method")
    result = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}}} if method == "initialize" else \
        {"tools": TOOLS} if method == "tools/list" else \
        {"content": [{"type": "text", "text": "server ran " + msg["params"]["name"]}]}
    print(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": result}), flush=True)
EOF
cat >"$work/mcp.yaml" <<EOF
version: 1
name: mcp
security: {level: standard}
agents: [{id: testagent}]
tools: [python3]
network: {mode: allowlist}
mcp:
  servers:
    - name: fake
      command: [python3, /home/sandbox/mcp/fake_mcp.py]
      deny_tools: [danger]
mounts:
  - {source: $work/mcp, target: /home/sandbox/mcp, readonly: true}
commands: {mode: unrestricted}
resources: {cpu: 1, memory: 1024, pids_limit: 256}
storage: {size: 5g}
persistence: ephemeral
EOF
"$rig" import "$work/mcp.yaml" >/dev/null
calls='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}
{"jsonrpc":"2.0","id":2,"method":"tools/list"}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{}}}
{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"danger","arguments":{}}}
{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"danger","Name":"echo","arguments":{}}}'
guard="printf '%s\n' '$calls' | rig-helper mcp-guard --policy /etc/rig/mcp/fake.json -- python3 /home/sandbox/mcp/fake_mcp.py"
"$rig" run mcp -- sh -c "$guard; sleep 4" </dev/null >"$work/out" 2>&1 || true
if grep -q '"name":"echo"' "$work/out" && ! grep -q '"name":"danger"' "$work/out"; then pass "a denied tool is hidden from the tool list"; else fail "a denied tool is hidden from the tool list"; show; fi
if grep -q 'server ran echo' "$work/out" && [ "$(grep -c 'server ran danger' "$work/out")" = 0 ]; then pass "allowed calls run; denied and ambiguous calls never reach the server"; else fail "allowed calls run; denied and ambiguous calls never reach the server"; show; fi
expect_output "MCP calls are in the audit log" 'mcp_tool_blocked' "$rig" audit mcp

echo "== gateway MCP server"
# A server in the gateway receives its ${VAR} secret; the sandbox reaches it
# only through the guard and never sees the secret itself.
cat >"$work/vault.py" <<'EOF'
import json, os, sys
for line in sys.stdin:
    msg = json.loads(line)
    if "id" not in msg:
        continue
    if msg.get("method") == "initialize":
        result = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}}}
    else:
        result = {"content": [{"type": "text", "text": "secret=" + os.environ.get("SECRET", "")}]}
    print(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": result}), flush=True)
EOF
vault_src="$(base64 -w0 "$work/vault.py")"
cat >"$work/gwmcp.yaml" <<EOF
version: 1
name: gwmcp
security: {level: standard}
agents: [{id: testagent}]
tools: [curl, python3]
network: {mode: allowlist}
mcp:
  servers:
    - name: vault
      command: [python3, -c, "import base64; exec(base64.b64decode('$vault_src'))"]
      run_in: gateway
      env: {SECRET: "\${RIG_IT_SECRET}"}
      allow_tools: [reveal]
commands: {mode: unrestricted}
resources: {cpu: 1, memory: 1024, pids_limit: 256}
storage: {size: 5g}
persistence: ephemeral
EOF
"$rig" import "$work/gwmcp.yaml" >/dev/null
cat >"$work/mcp-call.sh" <<'EOF'
url=http://rig-gw:8800/mcp/vault
sid=$(curl -sS -D - -o /dev/null -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' "$url" | tr -d '\r' | sed -n 's/^[Mm]cp-[Ss]ession-[Ii]d: //p')
curl -sS -H "Mcp-Session-Id: $sid" -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"reveal","arguments":{}}}' "$url"
EOF
mcp_call="$(cat "$work/mcp-call.sh")"
expect_output "a gateway MCP server receives its secret" 'secret=it-works' env RIG_IT_SECRET=it-works "$rig" run gwmcp -- sh -c "$mcp_call"
expect_output "the sandbox never sees that secret" '^absent$' env RIG_IT_SECRET=it-works "$rig" run gwmcp -- sh -c 'env | grep -q it-works && echo present || echo absent'

echo "== host ports"
echo "hello from the host" >"$work/www/index.html"
python3 -m http.server "$port" --bind 127.0.0.1 --directory "$work/www" >/dev/null 2>&1 &
web_pid=$!
sleep 1
"$rig" new relay --agent testagent --port "web:$port" >/dev/null
expect_output "a listed host port is reachable through the gateway" 'hello from the host' "$rig" run relay -- curl -fsS --max-time 30 "http://rig-gw:$port/"
expect 7 "an unlisted port is not" "$rig" run relay -- curl -sS -o /dev/null --max-time 10 "http://rig-gw:$((port + 1))/"
expect 0 "--keep-running hands the sandbox to a background monitor" "$rig" run relay --keep-running -- true
expect_output "the host port still works after that session left" 'hello from the host' "$rig" exec relay -- curl -fsS --max-time 30 "http://rig-gw:$port/"
"$rig" stop relay >/dev/null 2>&1 || true

if skipping claude; then
	echo "skip  the Claude Code image"
else
	echo "== Claude Code"
	"$rig" new cc --agent claude-code >/dev/null
	expect_output "Claude Code installs and starts in a standard sandbox" '[0-9]+\.[0-9]+' "$rig" run cc -- claude --version
fi

echo
echo "$passed passed, $failed failed"
[ "$failed" = 0 ]
