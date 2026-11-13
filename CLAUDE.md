# mcp-sentinel

A stdio proxy between an MCP client and a real MCP server. It scores every tool at startup and blocks risky `tools/call` requests before they reach the server.

- Run the tests with `python -m unittest discover -v`. CI runs the same on Python 3.12.
- Never weaken a test in `test_rules.py` or `test_sentinel.py` to make a change pass.

## Trunk vs leaf

Trunk (Opus author or reviewer, line-by-line diff read, `/code-review` high plus `security-review`):
- `sentinel.py`: the proxy. It decides what reaches the real server, redacts secrets and writes the audit log. A bug here lets an attack through silently.
- `rules.py`: tool risk scoring and payload attack patterns. A bad rule means missed attacks or false blocks.
- `requirements.txt`: the `mcp` SDK version changes protocol behaviour under the proxy.
- `.github/workflows/`: CI.

Leaf: `README.md`, `demo/`, `LICENSE`. Tests are leaf to add to, but never weaken them.
