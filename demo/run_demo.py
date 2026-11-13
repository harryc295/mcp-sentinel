"""Drives a sequence of normal and malicious tool calls through sentinel.py
in front of the fake support-agent server, for a clean recordable transcript.

The downstream subprocess's own stderr is redirected to a separate log file
(not our stdout) so the transcript we print is ours alone, in our order --
the raw audit trail is still readable afterwards in demo-audit.jsonl.
"""
import asyncio
import json
import pathlib

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

HERE = pathlib.Path(__file__).parent
SENTINEL = HERE.parent / "sentinel.py"
DOWNSTREAM = HERE / "fake_downstream.py"
AUDIT_LOG = HERE / "demo-audit.jsonl"

STEPS = [
    ("read_file", {"path": "tickets/2026-1183/screenshot.png"}, "normal attachment read"),
    ("read_file", {"path": "../../etc/passwd"}, "path traversal attempt"),
    ("fetch_url", {"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}, "SSRF to cloud metadata endpoint"),
    ("send_email", {"to": "customer@example.com", "body": "leaked key: ghp_abcdefghijklmnopqrstuvwx"}, "credential exfil in an outbound email"),
    ("delete_database", {"name": "prod_customers"}, "direct call to a hidden admin tool"),
]


def _print_startup_scan():
    print("$ mcp-sentinel startup scan (connects downstream, scores every tool)")
    for line in AUDIT_LOG.read_text().splitlines():
        record = json.loads(line)
        if record["event"] in ("startup_posture", "startup_classify"):
            label = record.get("tool", "server")
            print(f"  [{label}] {record.get('detail', '')}")


async def main():
    if AUDIT_LOG.exists():
        AUDIT_LOG.unlink()

    params = StdioServerParameters(
        command="python",
        args=[str(SENTINEL), "--block-severity", "high", "--log", str(AUDIT_LOG), "--", "python", str(DOWNSTREAM)],
        cwd=str(HERE),
    )
    with open(HERE / "sentinel-stderr.log", "w", encoding="utf-8") as errlog:
        async with stdio_client(params, errlog=errlog) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()

                print("=" * 72)
                print("mcp-sentinel demo: wrapping a support-agent MCP server")
                print("=" * 72)
                print()
                _print_startup_scan()

                tools = await session.list_tools()
                visible = [t.name for t in tools.tools]
                print("\n$ tools/list  (as seen by the client)")
                print(f"  visible tools: {visible}")
                print(f"  'delete_database' present: {'delete_database' in visible}")

                for name, args, label in STEPS:
                    print(f"\n$ tools/call {name}   # {label}")
                    print(f"  arguments: {args}")
                    result = await session.call_tool(name, args)
                    text = result.content[0].text if result.content else ""
                    verdict = "BLOCKED" if text.startswith("[mcp-sentinel]") else "ALLOWED"
                    print(f"  -> {verdict}: {text}")


if __name__ == "__main__":
    asyncio.run(main())
