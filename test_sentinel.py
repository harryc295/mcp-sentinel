"""Integration test: drive mcp-sentinel over the official SDK's in-memory
transport (no subprocess, no real downstream package needed) to prove it
blocks at the actual protocol level, not just in a unit test of rules.py."""
import asyncio
import json
import pathlib
import tempfile
import unittest

import mcp.types as types
from mcp.server.lowlevel import Server
from mcp.shared.memory import create_connected_server_and_client_session

from rules import classify_tools
from sentinel import _tool_to_dict, build_upstream_server


def _make_fake_downstream() -> Server:
    server = Server("fake-downstream")

    @server.list_tools()
    async def list_tools():
        return [
            types.Tool(name="get_weather", description="Returns the current weather for a city.",
                       inputSchema={"type": "object", "properties": {"city": {"type": "string"}}}),
            types.Tool(name="read_file", description="Reads a local file.",
                       inputSchema={"type": "object", "properties": {"path": {"type": "string"}}}),
            types.Tool(name="delete_database", description="Deletes a database.",
                       inputSchema={"type": "object", "properties": {"name": {"type": "string"}}}),
        ]

    @server.call_tool()
    async def call_tool(name, arguments):
        return [types.TextContent(type="text", text=f"executed {name} with {arguments}")]

    return server


class SentinelIntegrationTests(unittest.TestCase):
    def test_static_block_and_payload_block_both_take_effect_over_real_mcp_protocol(self):
        asyncio.run(self._scenario())

    async def _scenario(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_path = pathlib.Path(tmp) / "audit.jsonl"

            async with create_connected_server_and_client_session(_make_fake_downstream()) as downstream:
                await downstream.initialize()
                tools = (await downstream.list_tools()).tools
                severities = classify_tools([_tool_to_dict(t) for t in tools])

                upstream = build_upstream_server(downstream, severities, block_severity="high", log_path=log_path)

                async with create_connected_server_and_client_session(upstream) as client:
                    await client.initialize()

                    visible = {t.name for t in (await client.list_tools()).tools}
                    self.assertIn("get_weather", visible)
                    self.assertNotIn("delete_database", visible)  # high severity, hidden at list time too

                    ok = await client.call_tool("get_weather", {"city": "london"})
                    self.assertFalse(ok.isError)

                    blocked = await client.call_tool("delete_database", {"name": "prod"})
                    self.assertTrue(blocked.isError)

                    # read_file is only "medium" by static severity (passes the "high" threshold),
                    # but a path-traversal argument must still be blocked at call time.
                    traversal = await client.call_tool("read_file", {"path": "../../etc/passwd"})
                    self.assertTrue(traversal.isError)

            events = [json.loads(line) for line in log_path.read_text().splitlines()]
            calls = {(e["tool"], e["decision"]) for e in events if e["event"] == "call"}
            self.assertIn(("delete_database", "block"), calls)
            self.assertIn(("read_file", "block"), calls)
            self.assertIn(("get_weather", "allow"), calls)


if __name__ == "__main__":
    unittest.main()
