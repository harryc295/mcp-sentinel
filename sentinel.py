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
import pathlib
import sys
from datetime import datetime, timezone

import mcp.types as types
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

from rules import (
    SEVERITY_RANK,
    check_lethal_trifecta,
    check_payload,
    check_plaintext_secrets,
    check_unpinned_supply_chain,
    classify_tools,
    decide,
)


def _tool_to_dict(tool: types.Tool) -> dict:
    return {"name": tool.name, "description": tool.description or "", "inputSchema": tool.inputSchema or {}}


def _log(path: pathlib.Path, record: dict):
    record["ts"] = datetime.now(timezone.utc).isoformat()
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")
    print(f"[mcp-sentinel] {record['event']}: {record.get('reason', record.get('detail', ''))}", file=sys.stderr)


def build_upstream_server(downstream: ClientSession, severities: dict, block_severity: str, log_path: pathlib.Path) -> Server:
    server = Server("mcp-sentinel")

    @server.list_tools()
    async def handle_list_tools() -> list[types.Tool]:
        result = await downstream.list_tools()
        return [t for t in result.tools if SEVERITY_RANK[severities.get(t.name, ("low", []))[0]] < SEVERITY_RANK[block_severity]]

    @server.call_tool()
    async def handle_call_tool(name: str, arguments: dict):
        severity, reasons = severities.get(name, ("low", []))
        payload_flags = check_payload(name, "", arguments)
        decision, reason = decide(severity, payload_flags, block_severity)

        _log(log_path, {"event": "call", "tool": name, "arguments": arguments, "decision": decision, "reason": reason or "; ".join(reasons)})

        if decision == "block":
            return types.CallToolResult(content=[types.TextContent(type="text", text=f"[mcp-sentinel] blocked: {reason}")], isError=True)

        result = await downstream.call_tool(name, arguments)
        return result.content

    return server


async def run(command: str, args: list[str], env: dict, block_severity: str, log_path: pathlib.Path):
    server_params = StdioServerParameters(command=command, args=args, env=env or None)

    for detail in [check_unpinned_supply_chain(command, args), *check_plaintext_secrets(env)]:
        if detail:
            _log(log_path, {"event": "startup_posture", "detail": detail})

    async with stdio_client(server_params) as (down_read, down_write):
        async with ClientSession(down_read, down_write) as downstream:
            await downstream.initialize()
            tools_result = await downstream.list_tools()
            tool_dicts = [_tool_to_dict(t) for t in tools_result.tools]

            trifecta = check_lethal_trifecta(tool_dicts)
            if trifecta:
                _log(log_path, {"event": "startup_posture", "detail": trifecta})

            severities = classify_tools(tool_dicts)
            for name, (severity, reasons) in severities.items():
                if reasons:
                    _log(log_path, {"event": "startup_classify", "tool": name, "severity": severity, "detail": "; ".join(reasons)})

            upstream = build_upstream_server(downstream, severities, block_severity, log_path)
            async with stdio_server() as (up_read, up_write):
                await upstream.run(up_read, up_write, upstream.create_initialization_options())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--block-severity", choices=("low", "medium", "high", "critical"), default="critical",
                         help="Block tools/calls whose static severity is at or above this level")
    parser.add_argument("--log", type=pathlib.Path, default=pathlib.Path("mcp-sentinel-audit.jsonl"))
    parser.add_argument("--env", action="append", default=[], metavar="KEY=VALUE",
                         help="Env var to pass to the downstream server (repeatable)")
    parser.add_argument("downstream", nargs=argparse.REMAINDER,
                         help="The real server command, e.g. -- npx -y @modelcontextprotocol/server-github")
    args = parser.parse_args()

    downstream = args.downstream[1:] if args.downstream and args.downstream[0] == "--" else args.downstream
    if not downstream:
        parser.error("pass the downstream server command after '--', e.g. -- npx -y @modelcontextprotocol/server-github")
    command, *rest = downstream

    env = dict(pair.split("=", 1) for pair in args.env)

    asyncio.run(run(command, rest, env, args.block_severity, args.log))


if __name__ == "__main__":
    main()
