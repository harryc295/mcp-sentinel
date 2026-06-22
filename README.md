# mcp-sentinel

A proxy that sits between an MCP client and a real MCP server. It scores
every tool the server exposes, then inspects the arguments on every
`tools/call` before forwarding it. Calls that match a risk threshold or a
live attack pattern get blocked instead of logged after the fact.

## Why

Static scanners read tool descriptions once and write a report. They never
see what arguments a model sends. An attacker who poisons a tool
description, or a model that gets tricked into passing `../../etc/passwd`
as a path, slips past a one-time audit. mcp-sentinel sits in the call path
and checks both: the tool definition at connect time, and the live payload
on every call.

## Quickstart

```sh
pip install -r requirements.txt
python sentinel.py --block-severity high -- npx -y @modelcontextprotocol/server-github
```

Point your MCP client at `python sentinel.py -- <real command>` instead of
the real command directly. In a Claude Desktop / Claude Code config:

```json
{
  "mcpServers": {
    "github": {
      "command": "python",
      "args": ["sentinel.py", "--block-severity", "high", "--", "npx", "-y", "@modelcontextprotocol/server-github"],
      "env": { "GITHUB_TOKEN": "ghp_..." }
    }
  }
}
```

mcp-sentinel writes every call to `mcp-sentinel-audit.jsonl`: timestamp,
tool, arguments, decision, reason.

## What it catches

| Check | When | Catches |
|---|---|---|
| `injection_phrase_in_description` | connect | A tool description carrying hidden instructions for the model |
| `destructive_without_confirmation` | connect | A delete/exec-shaped tool with no confirm or dry_run parameter |
| `lethal_trifecta` | connect | One server combining untrusted input, private data, and an exfil path |
| `unpinned_package_supply_chain` | connect | An `npx`/`uvx` launch with no version pin |
| `plaintext_secret_in_config` | connect | A credential sitting in plaintext in the launch env |
| Path traversal | call | A path argument reaching outside its intended directory |
| SSRF | call | A URL argument pointing at a loopback or private address, including the cloud metadata endpoint |
| Shell injection | call | Shell metacharacters in an argument going into an exec-shaped tool |
| Credential exfil | call | A token-shaped string going out through a send/post-shaped tool |

Connect-time findings set a tool's severity. `--block-severity` decides the
cutoff: the proxy hides tools at or above it from the client's tool list and
rejects them if called anyway. Call-time findings always block, independent
of the threshold. They describe what happened in this one call.

## How it works

mcp-sentinel runs the official `mcp` SDK on both sides. Downstream, it opens
a real client session against the wrapped server. Upstream, it runs its own
server that the calling client talks to. Every `tools/list` and `tools/call`
passes through `rules.py` before it reaches either side.

`test_sentinel.py` proves this over the SDK's in-memory transport: a fake
downstream server, a real sentinel instance in front of it, a real client
session on top, and assertions that a blocked tool never appears in the
tool list and a malicious argument gets rejected mid-call. No subprocess
required to run it.

## Limits

The rules are pattern matches; no model judges intent here. A renamed tool
(`del_db` instead of `delete_database`) can dodge the keyword check. SSRF
detection is lexical, checking the hostname in the URL string rather than
where it resolves at request time. Pair this with code review and
least-privilege scoping on the tools themselves.

## License

MIT
