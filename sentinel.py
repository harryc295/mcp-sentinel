#!/usr/bin/env python3
"""mcp-sentinel: a transparent MCP proxy that sits between a client (Claude
Desktop/Code, etc.) and a real MCP server, scores the server's tools at
connect time, and inspects every tools/call payload before forwarding it --
blocking calls that match a risk threshold or a call-time attack pattern
(path traversal, SSRF, shell injection, credential exfil) instead of just
reporting on them after the fact.
"""
import argparse
import asyncio
import json
import os
import pathlib
import re
import sys
from datetime import datetime, timedelta, timezone

import mcp.types as types
from mcp import ClientSession, McpError
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.server.lowlevel import Server
from mcp.server.lowlevel.helper_types import ReadResourceContents
from mcp.server.stdio import stdio_server

from rules import (
    SEVERITY_RANK,
    _SECRET_VALUE_RE,
    check_lethal_trifecta,
    check_payload,
    check_plaintext_secrets,
    check_unpinned_supply_chain,
    classify_tools,
    decide,
)

MAX_ARGUMENT_BYTES = 64_000  # DoS guard: a multi-MB argument blob isn't a real tool call


def _tool_to_dict(tool: types.Tool) -> dict:
    return {"name": tool.name, "description": tool.description or "", "inputSchema": tool.inputSchema or {}}


def _redact(value):
    """Audit logs are meant to be read and shared; a credential the proxy
    just caught shouldn't end up sitting in plaintext in its own log file."""
    if isinstance(value, str):
        return _SECRET_VALUE_RE.sub("[redacted]", value)
    if isinstance(value, dict):
        return {k: _redact(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact(v) for v in value]
    return value


def _log(path: pathlib.Path, record: dict):
    record["ts"] = datetime.now(timezone.utc).isoformat()
    if "arguments" in record:
        record["arguments"] = _redact(record["arguments"])
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")
    print(f"[mcp-sentinel] {record['event']}: {record.get('reason', record.get('detail', ''))}", file=sys.stderr)


def build_upstream_server(downstream: ClientSession, severities: dict, block_severity: str, log_path: pathlib.Path,
                           capabilities, call_timeout: float | None) -> Server:
    server = Server("mcp-sentinel")
    timeout = timedelta(seconds=call_timeout) if call_timeout else None

    @server.list_tools()
    async def handle_list_tools() -> list[types.Tool]:
        result = await downstream.list_tools()
        return [t for t in result.tools if SEVERITY_RANK[severities.get(t.name, ("low", []))[0]] < SEVERITY_RANK[block_severity]]

    @server.call_tool()
    async def handle_call_tool(name: str, arguments: dict):
        size = len(json.dumps(arguments or {}))
        if size > MAX_ARGUMENT_BYTES:
            _log(log_path, {"event": "call", "tool": name, "arguments": "<omitted, too large>", "decision": "block",
                             "reason": f"argument payload is {size} bytes, over the {MAX_ARGUMENT_BYTES}-byte limit"})
            return types.CallToolResult(content=[types.TextContent(type="text", text="[mcp-sentinel] blocked: argument payload too large")], isError=True)

        severity, reasons = severities.get(name, ("low", []))
        payload_flags = check_payload(name, "", arguments)
        decision, reason = decide(severity, payload_flags, block_severity)

        _log(log_path, {"event": "call", "tool": name, "arguments": arguments, "decision": decision, "reason": reason or "; ".join(reasons)})

        if decision == "block":
            return types.CallToolResult(content=[types.TextContent(type="text", text=f"[mcp-sentinel] blocked: {reason}")], isError=True)

        try:
            result = await downstream.call_tool(name, arguments, read_timeout_seconds=timeout)
        except McpError as e:
            # A timed-out call surfaces as McpError too (the SDK converts anyio's
            # TimeoutError before it reaches us) -- one branch covers both cases.
            _log(log_path, {"event": "call", "tool": name, "arguments": "<omitted, already logged above>", "decision": "downstream_error", "reason": str(e)})
            return types.CallToolResult(content=[types.TextContent(type="text", text=f"[mcp-sentinel] downstream error: {e}")], isError=True)
        return result.content

    if capabilities.resources:
        @server.list_resources()
        async def handle_list_resources():
            return (await downstream.list_resources()).resources

        @server.read_resource()
        async def handle_read_resource(uri):
            result = await downstream.read_resource(uri)
            return [
                ReadResourceContents(content=c.text if isinstance(c, types.TextResourceContents) else c.blob, mime_type=c.mimeType)
                for c in result.contents
            ]

        @server.list_resource_templates()
        async def handle_list_resource_templates():
            return (await downstream.list_resource_templates()).resourceTemplates

    if capabilities.prompts:
        @server.list_prompts()
        async def handle_list_prompts():
            return (await downstream.list_prompts()).prompts

        @server.get_prompt()
        async def handle_get_prompt(name, arguments):
            return await downstream.get_prompt(name, arguments)

    return server


def _effective_env(explicit_env: dict) -> dict:
    """The SDK's own default only forwards a curated allowlist of "safe" env
    vars to the child, not mcp-sentinel's environment -- so a token set via
    an MCP client's "env" block on *this* process would otherwise silently
    never reach the server it was meant for. Forward everything, the same
    as if the client had launched the real command directly."""
    return {**os.environ, **explicit_env}


async def run(command: str, args: list[str], env: dict, block_severity: str, log_path: pathlib.Path, call_timeout: float | None):
    server_params = StdioServerParameters(command=command, args=args, env=_effective_env(env))

    for detail in [check_unpinned_supply_chain(command, args), *check_plaintext_secrets(env)]:
        if detail:
            _log(log_path, {"event": "startup_posture", "detail": detail})

    async with stdio_client(server_params) as (down_read, down_write):
        async with ClientSession(down_read, down_write) as downstream:
            init_result = await downstream.initialize()
            tools_result = await downstream.list_tools()
            tool_dicts = [_tool_to_dict(t) for t in tools_result.tools]

            trifecta = check_lethal_trifecta(tool_dicts)
            if trifecta:
                _log(log_path, {"event": "startup_posture", "detail": trifecta})

            severities = classify_tools(tool_dicts)
            for name, (severity, reasons) in severities.items():
                if reasons:
                    _log(log_path, {"event": "startup_classify", "tool": name, "severity": severity, "detail": "; ".join(reasons)})

            upstream = build_upstream_server(downstream, severities, block_severity, log_path, init_result.capabilities, call_timeout)
            async with stdio_server() as (up_read, up_write):
                await upstream.run(up_read, up_write, upstream.create_initialization_options())


def _parse_env(pairs: list[str]) -> dict:
    env = {}
    for pair in pairs:
        if "=" not in pair:
            raise SystemExit(f"--env expects KEY=VALUE, got: {pair!r}")
        key, value = pair.split("=", 1)
        env[key] = value
    return env


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--block-severity", choices=("low", "medium", "high", "critical"), default="critical",
                         help="Block tools/calls whose static severity is at or above this level")
    parser.add_argument("--log", type=pathlib.Path, default=pathlib.Path("mcp-sentinel-audit.jsonl"))
    parser.add_argument("--env", action="append", default=[], metavar="KEY=VALUE",
                         help="Env var to pass to the downstream server (repeatable)")
    parser.add_argument("--call-timeout", type=float, default=30.0,
                         help="Seconds to wait for a downstream tool call before giving up (0 disables the timeout)")
    parser.add_argument("downstream", nargs=argparse.REMAINDER,
                         help="The real server command, e.g. -- npx -y @modelcontextprotocol/server-github")
    args = parser.parse_args()

    downstream = args.downstream[1:] if args.downstream and args.downstream[0] == "--" else args.downstream
    if not downstream:
        parser.error("pass the downstream server command after '--', e.g. -- npx -y @modelcontextprotocol/server-github")
    command, *rest = downstream

    env = _parse_env(args.env)
    call_timeout = args.call_timeout or None

    try:
        asyncio.run(run(command, rest, env, args.block_severity, args.log, call_timeout))
    except* Exception as eg:
        for e in _leaf_exceptions(eg):
            print(f"[mcp-sentinel] fatal: downstream server unavailable or crashed: {e}", file=sys.stderr)
        sys.exit(1)


def _leaf_exceptions(exc):
    if isinstance(exc, BaseExceptionGroup):
        for sub in exc.exceptions:
            yield from _leaf_exceptions(sub)
    else:
        yield exc


if __name__ == "__main__":
    main()
