"""Integration test: drive mcp-sentinel over the official SDK's in-memory
transport (no subprocess, no real downstream package needed) to prove it
blocks at the actual protocol level, not just in a unit test of rules.py."""
import asyncio
import json
import os
import pathlib
import tempfile
import unittest

import mcp.types as types
from mcp.server.lowlevel import Server
from mcp.shared.memory import create_connected_server_and_client_session

from rules import classify_tools
from sentinel import _effective_env, _parse_env, _redact, _tool_to_dict, build_upstream_server


def _make_fake_downstream(with_resources=False) -> Server:
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

    if with_resources:
        @server.list_resources()
        async def list_resources():
            return [types.Resource(uri="file:///notes.txt", name="notes.txt")]

        @server.read_resource()
        async def read_resource(uri):
            return "hello from a resource"

    return server


class SentinelIntegrationTests(unittest.TestCase):
    def test_static_block_and_payload_block_both_take_effect_over_real_mcp_protocol(self):
        asyncio.run(self._scenario())

    async def _scenario(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_path = pathlib.Path(tmp) / "audit.jsonl"

            async with create_connected_server_and_client_session(_make_fake_downstream()) as downstream:
                init_result = await downstream.initialize()
                tools = (await downstream.list_tools()).tools
                severities = classify_tools([_tool_to_dict(t) for t in tools])

                upstream = build_upstream_server(downstream, severities, "high", log_path, init_result.capabilities, call_timeout=None)

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

                    oversized = await client.call_tool("read_file", {"path": "x" * 100_000})
                    self.assertTrue(oversized.isError)

            events = [json.loads(line) for line in log_path.read_text().splitlines()]
            calls = {(e["tool"], e["decision"]) for e in events if e["event"] == "call"}
            self.assertIn(("delete_database", "block"), calls)
            self.assertIn(("read_file", "block"), calls)
            self.assertIn(("get_weather", "allow"), calls)

    def test_resources_pass_through_when_downstream_supports_them(self):
        asyncio.run(self._resources_scenario())

    async def _resources_scenario(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_path = pathlib.Path(tmp) / "audit.jsonl"
            async with create_connected_server_and_client_session(_make_fake_downstream(with_resources=True)) as downstream:
                init_result = await downstream.initialize()
                tools = (await downstream.list_tools()).tools
                severities = classify_tools([_tool_to_dict(t) for t in tools])
                upstream = build_upstream_server(downstream, severities, "high", log_path, init_result.capabilities, call_timeout=None)

                async with create_connected_server_and_client_session(upstream) as client:
                    await client.initialize()
                    resources = (await client.list_resources()).resources
                    self.assertEqual([r.name for r in resources], ["notes.txt"])
                    content = await client.read_resource(resources[0].uri)
                    self.assertIn("hello from a resource", content.contents[0].text)

    def test_resources_are_not_falsely_advertised_when_downstream_lacks_them(self):
        asyncio.run(self._no_resources_scenario())

    async def _no_resources_scenario(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_path = pathlib.Path(tmp) / "audit.jsonl"
            async with create_connected_server_and_client_session(_make_fake_downstream(with_resources=False)) as downstream:
                init_result = await downstream.initialize()
                tools = (await downstream.list_tools()).tools
                severities = classify_tools([_tool_to_dict(t) for t in tools])
                upstream = build_upstream_server(downstream, severities, "high", log_path, init_result.capabilities, call_timeout=None)

                async with create_connected_server_and_client_session(upstream) as client:
                    await client.initialize()
                    with self.assertRaises(Exception):
                        await client.list_resources()


class RedactTests(unittest.TestCase):
    def test_credential_shaped_string_gets_redacted(self):
        self.assertEqual(_redact("key: ghp_abcdefghijklmnopqrstuvwx"), "key: [redacted]")

    def test_redact_walks_nested_structures(self):
        redacted = _redact({"body": ["fine", "token ghp_abcdefghijklmnopqrstuvwx"]})
        self.assertNotIn("ghp_", redacted["body"][1])

    def test_ordinary_values_pass_through_untouched(self):
        self.assertEqual(_redact({"city": "london"}), {"city": "london"})


class ParseEnvTests(unittest.TestCase):
    def test_parses_key_value_pairs(self):
        self.assertEqual(_parse_env(["A=1", "B=2"]), {"A": "1", "B": "2"})

    def test_rejects_a_pair_with_no_equals_sign(self):
        with self.assertRaises(SystemExit):
            _parse_env(["NOVALUE"])


class EffectiveEnvTests(unittest.TestCase):
    def test_inherits_the_full_process_environment_not_just_a_curated_allowlist(self):
        os.environ["MCP_SENTINEL_TEST_VAR"] = "from-process-env"
        try:
            self.assertEqual(_effective_env({})["MCP_SENTINEL_TEST_VAR"], "from-process-env")
        finally:
            del os.environ["MCP_SENTINEL_TEST_VAR"]

    def test_explicit_env_overrides_the_process_environment(self):
        os.environ["MCP_SENTINEL_TEST_VAR"] = "from-process-env"
        try:
            self.assertEqual(_effective_env({"MCP_SENTINEL_TEST_VAR": "from-cli"})["MCP_SENTINEL_TEST_VAR"], "from-cli")
        finally:
            del os.environ["MCP_SENTINEL_TEST_VAR"]


if __name__ == "__main__":
    unittest.main()
