"""Integration test: drive mcp-sentinel over the official SDK's in-memory
transport (no subprocess, no real downstream package needed) to prove it
blocks at the actual protocol level, not just in a unit test of rules.py."""
import asyncio
import json
import os
import pathlib
import tempfile
import unittest
from contextlib import asynccontextmanager

import anyio
import mcp.types as types
from mcp import ClientSession
from mcp.client._memory import InMemoryTransport
from mcp.server.lowlevel import Server

from rules import classify_tools
from sentinel import _effective_env, _parse_env, _redact, _tool_to_dict, build_upstream_server


@asynccontextmanager
async def _connect(server: Server):
    """A ClientSession wired to `server` in memory: the same client type sentinel uses for real."""
    async with InMemoryTransport(server) as (read, write):
        async with ClientSession(read, write) as session:
            yield session


def _make_fake_downstream(with_resources=False, slow_tool_seconds=0.0) -> Server:
    async def list_tools(ctx, params):
        return types.ListToolsResult(tools=[
            types.Tool(name="get_weather", description="Returns the current weather for a city.",
                       input_schema={"type": "object", "properties": {"city": {"type": "string"}}}),
            types.Tool(name="read_file", description="Reads a local file.",
                       input_schema={"type": "object", "properties": {"path": {"type": "string"}}}),
            types.Tool(name="delete_database", description="Deletes a database.",
                       input_schema={"type": "object", "properties": {"name": {"type": "string"}}}),
        ])

    async def call_tool(ctx, params):
        if slow_tool_seconds:
            await anyio.sleep(slow_tool_seconds)
        return types.CallToolResult(content=[types.TextContent(type="text", text=f"executed {params.name} with {params.arguments}")])

    async def list_resources(ctx, params):
        return types.ListResourcesResult(resources=[types.Resource(uri="file:///notes.txt", name="notes.txt")])

    async def read_resource(ctx, params):
        return types.ReadResourceResult(contents=[types.TextResourceContents(uri=params.uri, text="hello from a resource")])

    resource_handlers = {"on_list_resources": list_resources, "on_read_resource": read_resource} if with_resources else {}
    return Server("fake-downstream", on_list_tools=list_tools, on_call_tool=call_tool, **resource_handlers)


class SentinelIntegrationTests(unittest.TestCase):
    def test_static_block_and_payload_block_both_take_effect_over_real_mcp_protocol(self):
        asyncio.run(self._scenario())

    async def _scenario(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_path = pathlib.Path(tmp) / "audit.jsonl"

            async with _connect(_make_fake_downstream()) as downstream:
                init_result = await downstream.initialize()
                tools = (await downstream.list_tools()).tools
                severities = classify_tools([_tool_to_dict(t) for t in tools])

                upstream = build_upstream_server(downstream, severities, "high", log_path, init_result.capabilities, call_timeout=None)

                async with _connect(upstream) as client:
                    await client.initialize()

                    visible = {t.name for t in (await client.list_tools()).tools}
                    self.assertIn("get_weather", visible)
                    self.assertNotIn("delete_database", visible)  # high severity, hidden at list time too

                    ok = await client.call_tool("get_weather", {"city": "london"})
                    self.assertFalse(ok.is_error)

                    blocked = await client.call_tool("delete_database", {"name": "prod"})
                    self.assertTrue(blocked.is_error)

                    # read_file is only "medium" by static severity (passes the "high" threshold),
                    # but a path-traversal argument must still be blocked at call time.
                    traversal = await client.call_tool("read_file", {"path": "../../etc/passwd"})
                    self.assertTrue(traversal.is_error)

                    oversized = await client.call_tool("read_file", {"path": "x" * 100_000})
                    self.assertTrue(oversized.is_error)

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
            async with _connect(_make_fake_downstream(with_resources=True)) as downstream:
                init_result = await downstream.initialize()
                tools = (await downstream.list_tools()).tools
                severities = classify_tools([_tool_to_dict(t) for t in tools])
                upstream = build_upstream_server(downstream, severities, "high", log_path, init_result.capabilities, call_timeout=None)

                async with _connect(upstream) as client:
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
            async with _connect(_make_fake_downstream(with_resources=False)) as downstream:
                init_result = await downstream.initialize()
                tools = (await downstream.list_tools()).tools
                severities = classify_tools([_tool_to_dict(t) for t in tools])
                upstream = build_upstream_server(downstream, severities, "high", log_path, init_result.capabilities, call_timeout=None)

                async with _connect(upstream) as client:
                    await client.initialize()
                    with self.assertRaises(Exception):
                        await client.list_resources()

    def test_a_slow_downstream_call_times_out_as_an_error_not_a_hang(self):
        asyncio.run(self._timeout_scenario())

    async def _timeout_scenario(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_path = pathlib.Path(tmp) / "audit.jsonl"
            async with _connect(_make_fake_downstream(slow_tool_seconds=5)) as downstream:
                init_result = await downstream.initialize()
                tools = (await downstream.list_tools()).tools
                severities = classify_tools([_tool_to_dict(t) for t in tools])
                upstream = build_upstream_server(downstream, severities, "high", log_path, init_result.capabilities, call_timeout=0.2)

                async with _connect(upstream) as client:
                    await client.initialize()
                    with anyio.fail_after(3):
                        result = await client.call_tool("get_weather", {"city": "london"})
                    self.assertTrue(result.is_error)

            decisions = [json.loads(line)["decision"] for line in log_path.read_text().splitlines()]
            self.assertIn("downstream_error", decisions)

    def test_unscored_tools_on_later_list_pages_are_not_exposed(self):
        asyncio.run(self._pagination_scenario())

    async def _pagination_scenario(self):
        async def list_tools(ctx, params):
            if params and params.cursor == "page2":
                return types.ListToolsResult(tools=[types.Tool(name="run_shell", description="Runs a shell command.",
                                                               input_schema={"type": "object", "properties": {"cmd": {"type": "string"}}})])
            return types.ListToolsResult(tools=[types.Tool(name="get_weather", description="Returns the weather.",
                                                           input_schema={"type": "object"})], next_cursor="page2")

        async def call_tool(ctx, params):
            return types.CallToolResult(content=[types.TextContent(type="text", text="ok")])

        paginated = Server("paginated-downstream", on_list_tools=list_tools, on_call_tool=call_tool)
        with tempfile.TemporaryDirectory() as tmp:
            log_path = pathlib.Path(tmp) / "audit.jsonl"
            async with _connect(paginated) as downstream:
                init_result = await downstream.initialize()
                tools = (await downstream.list_tools()).tools
                severities = classify_tools([_tool_to_dict(t) for t in tools])
                upstream = build_upstream_server(downstream, severities, "high", log_path, init_result.capabilities, call_timeout=None)

                async with _connect(upstream) as client:
                    await client.initialize()
                    listed = await client.list_tools()
                    self.assertIsNone(listed.next_cursor)
                    self.assertEqual([t.name for t in listed.tools], ["get_weather"])


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
