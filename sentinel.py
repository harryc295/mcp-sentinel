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
import sys
from datetime import datetime, timezone

import mcp.types as types
from mcp import ClientSession, MCPError
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.server.lowlevel import Server
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
MAX_TOOL_PAGES = 100  # a downstream that never stops paging must not hang startup or tools/list


async def list_all_tools(downstream: ClientSession) -> list[types.Tool]:
    """Every tools/list page. Stops at MAX_TOOL_PAGES or a repeated cursor; a tool past
    that point is never scored, and calls to unscored tools are blocked."""
    tools, cursor, seen = [], None, set()
    for _ in range(MAX_TOOL_PAGES):
        result = await downstream.list_tools(params=types.PaginatedRequestParams(cursor=cursor) if cursor else None)
        tools.extend(result.tools)
        cursor = result.next_cursor
        if not cursor or cursor in seen:
            break
        seen.add(cursor)
    return tools


def _tool_to_dict(tool: types.Tool) -> dict:
    return {"name": tool.name, "description": tool.description or "", "inputSchema": tool.input_schema or {}}


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


def _blocked(text: str) -> types.CallToolResult:
    return types.CallToolResult(content=[types.TextContent(type="text", text=f"[mcp-sentinel] {text}")], is_error=True)


def build_upstream_server(downstream: ClientSession, severities: dict, block_severity: str, log_path: pathlib.Path,
                           capabilities, call_timeout: float | None) -> Server:
    def _check_or_refuse(event: str, target: str, arguments: dict):
        """resources/read and prompts/get carry attacker-reachable input too (a URI, prompt
        arguments): run the same payload checks as tools/call and refuse with an error."""
        flags = check_payload(target, "", arguments)
        _log(log_path, {"event": event, "target": target, "arguments": arguments,
                         "decision": "block" if flags else "allow", "reason": "; ".join(flags)})
        if flags:
            raise MCPError(types.INVALID_PARAMS, f"[mcp-sentinel] blocked: {'; '.join(flags)}")

    async def handle_list_tools(ctx, params) -> types.ListToolsResult:
        # One merged list, no cursor. Only tools scored at startup are listed: a tool that
        # appeared later was never scored, and handle_call_tool blocks it anyway.
        tools = await list_all_tools(downstream)
        visible = [t for t in tools if t.name in severities and SEVERITY_RANK[severities[t.name][0]] < SEVERITY_RANK[block_severity]]
        return types.ListToolsResult(tools=visible)

    async def handle_call_tool(ctx, params: types.CallToolRequestParams) -> types.CallToolResult:
        name, arguments = params.name, params.arguments or {}
        size = len(json.dumps(arguments))
        if size > MAX_ARGUMENT_BYTES:
            _log(log_path, {"event": "call", "tool": name, "arguments": "<omitted, too large>", "decision": "block",
                             "reason": f"argument payload is {size} bytes, over the {MAX_ARGUMENT_BYTES}-byte limit"})
            return _blocked("blocked: argument payload too large")

        if name not in severities:
            reason = "tool was not listed when mcp-sentinel started, so it was never scored"
            _log(log_path, {"event": "call", "tool": name, "arguments": arguments, "decision": "block", "reason": reason})
            return _blocked(f"blocked: {reason}")

        severity, reasons = severities[name]
        payload_flags = check_payload(name, "", arguments)
        decision, reason = decide(severity, payload_flags, block_severity)

        _log(log_path, {"event": "call", "tool": name, "arguments": arguments, "decision": decision, "reason": reason or "; ".join(reasons)})

        if decision == "block":
            return _blocked(f"blocked: {reason}")

        try:
            result = await downstream.call_tool(name, arguments, read_timeout_seconds=call_timeout)
        except (MCPError, RuntimeError) as e:
            # MCPError covers downstream errors and timeouts (the SDK converts the timeout
            # before it reaches us). RuntimeError is how the 2.x SDK refuses an "input
            # required" or claimed reply: neither is proxied, so the call fails closed.
            _log(log_path, {"event": "call", "tool": name, "arguments": "<omitted, already logged above>", "decision": "downstream_error", "reason": str(e)})
            return _blocked(f"downstream error: {e}")
        return result

    handlers = {"on_list_tools": handle_list_tools, "on_call_tool": handle_call_tool}

    if capabilities.resources:
        async def handle_list_resources(ctx, params) -> types.ListResourcesResult:
            return await downstream.list_resources(params=params)

        async def handle_read_resource(ctx, params: types.ReadResourceRequestParams) -> types.ReadResourceResult:
            _check_or_refuse("resource_read", "resources/read", {"uri": params.uri})
            return await downstream.read_resource(params.uri)

        async def handle_list_resource_templates(ctx, params) -> types.ListResourceTemplatesResult:
            return await downstream.list_resource_templates(params=params)

        handlers.update(on_list_resources=handle_list_resources, on_read_resource=handle_read_resource,
                        on_list_resource_templates=handle_list_resource_templates)

    if capabilities.prompts:
        async def handle_list_prompts(ctx, params) -> types.ListPromptsResult:
            return await downstream.list_prompts(params=params)

        async def handle_get_prompt(ctx, params: types.GetPromptRequestParams) -> types.GetPromptResult:
            _check_or_refuse("prompt_get", f"prompts/get {params.name}", params.arguments or {})
            return await downstream.get_prompt(params.name, params.arguments)

        handlers.update(on_list_prompts=handle_list_prompts, on_get_prompt=handle_get_prompt)

    return Server("mcp-sentinel", **handlers)


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
            tool_dicts = [_tool_to_dict(t) for t in await list_all_tools(downstream)]

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
