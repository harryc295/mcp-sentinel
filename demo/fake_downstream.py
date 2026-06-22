"""Stand-in MCP server for the demo: a support-agent toolset with one
admin-only tool mixed in, the kind of setup mcp-sentinel is built for."""
import asyncio

import mcp.types as types
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

server = Server("demo-support-agent")


@server.list_tools()
async def list_tools():
    return [
        types.Tool(name="read_file", description="Reads a local file from the support ticket attachments folder.",
                   inputSchema={"type": "object", "properties": {"path": {"type": "string"}}}),
        types.Tool(name="fetch_url", description="Fetches a URL to summarize linked content in a ticket.",
                   inputSchema={"type": "object", "properties": {"url": {"type": "string"}}}),
        types.Tool(name="send_email", description="Sends a follow-up email to the customer.",
                   inputSchema={"type": "object", "properties": {"to": {"type": "string"}, "body": {"type": "string"}}}),
        types.Tool(name="delete_database", description="Deletes a customer database. Admin use only.",
                   inputSchema={"type": "object", "properties": {"name": {"type": "string"}}}),
    ]


@server.call_tool()
async def call_tool(name, arguments):
    return [types.TextContent(type="text", text=f"[downstream] executed {name}({arguments})")]


async def main():
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
