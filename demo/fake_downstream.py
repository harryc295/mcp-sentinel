"""Stand-in MCP server for the demo: a support-agent toolset with one
admin-only tool mixed in, the kind of setup mcp-sentinel is built for."""
import asyncio

import mcp.types as types
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

async def list_tools(ctx, params):
    return types.ListToolsResult(tools=[
        types.Tool(name="read_file", description="Reads a local file from the support ticket attachments folder.",
                   input_schema={"type": "object", "properties": {"path": {"type": "string"}}}),
        types.Tool(name="fetch_url", description="Fetches a URL to summarize linked content in a ticket.",
                   input_schema={"type": "object", "properties": {"url": {"type": "string"}}}),
        types.Tool(name="send_email", description="Sends a follow-up email to the customer.",
                   input_schema={"type": "object", "properties": {"to": {"type": "string"}, "body": {"type": "string"}}}),
        types.Tool(name="delete_database", description="Deletes a customer database. Admin use only.",
                   input_schema={"type": "object", "properties": {"name": {"type": "string"}}}),
    ])


async def call_tool(ctx, params):
    return types.CallToolResult(content=[types.TextContent(type="text", text=f"[downstream] executed {params.name}({params.arguments})")])


server = Server("demo-support-agent", on_list_tools=list_tools, on_call_tool=call_tool)


async def main():
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
