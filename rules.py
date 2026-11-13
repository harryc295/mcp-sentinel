"""Risk rules for MCP tool definitions, server launch configs, and the live
arguments passed in a tools/call request.

ponytail: keyword/pattern heuristics, not a semantic parser -- tune the
keyword lists as real findings come in. SSRF/host checks are lexical only,
no DNS resolution, so a hostname that resolves to an internal IP at request
time slips through; add a resolve-and-check step if that matters more than
the extra network round trip it costs.
"""
import ipaddress
import re
import socket
from dataclasses import dataclass
from typing import Callable, Optional
from urllib.parse import urlsplit

SEVERITIES = ("low", "medium", "high", "critical")
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}


@dataclass
class Rule:
    id: str
    severity: str
    summary: str
    check: Callable[[dict], Optional[str]]  # tool dict -> detail string if violated, else None


_DESTRUCTIVE_KEYWORDS = (
    "exec", "eval", "shell", "subprocess", "delete", "remove", "drop",
    "sudo", "kill", "wipe", "truncate", "overwrite", "rm_",
)
_CONFIRM_PARAM_HINTS = ("confirm", "dry_run", "dryrun", "force")


def _has_keyword(text: str, keywords) -> Optional[str]:
    """Word-boundary keyword search -- plain substring matching flagged
    'information' as destructive because it contains 'format'. Anchoring to
    a word start avoids that without losing matches on suffixes like
    'deletes'/'deletion'."""
    return next((kw for kw in keywords if re.search(rf"\b{re.escape(kw)}", text)), None)

_INJECTION_PHRASES = (
    "ignore previous instructions", "ignore all previous", "disregard the system prompt",
    "disregard your instructions", "do not tell the user", "without telling the user",
    "do not mention this to", "without informing the user", "this is not a test",
)
_IMPERATIVE_PHRASES = (
    "you must always", "always call this tool first", "always use this tool first",
    "never refuse", "always respond by calling",
)

_CONSTRAINABLE_PARAM_NAMES = ("path", "file", "command", "cmd", "query", "sql", "url")
_LONG_DESCRIPTION_THRESHOLD = 800


def _text(tool: dict) -> str:
    return f"{tool.get('name', '')} {tool.get('description', '')}".lower()


def _check_destructive_without_confirmation(tool: dict) -> Optional[str]:
    text = _text(tool)
    hit = _has_keyword(text, _DESTRUCTIVE_KEYWORDS)
    if not hit:
        return None
    props = tool.get("inputSchema", {}).get("properties", {})
    if any(hint in p.lower() for p in props for hint in _CONFIRM_PARAM_HINTS):
        return None
    return f"name/description suggests a destructive action ('{hit}') with no confirm/dry_run/force parameter"


def _model_visible_text(tool: dict) -> str:
    """The description plus any other text the client may show the model (title, schema
    descriptions, annotations), which callers pass in as `otherText`."""
    return f"{tool.get('description', '')} {tool.get('otherText', '')}".lower()


def _check_injection_phrase(tool: dict) -> Optional[str]:
    text = _model_visible_text(tool)
    hit = next((p for p in _INJECTION_PHRASES if p in text), None)
    return f"description or other tool text contains a prompt-injection-style phrase: '{hit}'" if hit else None


def _check_imperative_phrase(tool: dict) -> Optional[str]:
    text = _model_visible_text(tool)
    hit = next((p for p in _IMPERATIVE_PHRASES if p in text), None)
    return f"description or other tool text gives the model a meta-behavioral directive: '{hit}'" if hit else None


def _check_unconstrained_param(tool: dict) -> Optional[str]:
    props = tool.get("inputSchema", {}).get("properties", {})
    for name, schema in props.items():
        if schema.get("type") != "string":
            continue
        if not any(n in name.lower() for n in _CONSTRAINABLE_PARAM_NAMES):
            continue
        if "enum" in schema or "pattern" in schema:
            continue
        return f"parameter '{name}' takes unconstrained free-text but its name implies a path/command/query"
    return None


def _check_long_description(tool: dict) -> Optional[str]:
    desc = tool.get("description", "")
    if len(desc) > _LONG_DESCRIPTION_THRESHOLD:
        return f"description is {len(desc)} chars -- unusually long descriptions can hide injected instructions"
    return None


RULES = [
    Rule("destructive_without_confirmation", "high", "Destructive-sounding tool with no confirmation parameter", _check_destructive_without_confirmation),
    Rule("injection_phrase_in_description", "critical", "Tool description contains a known prompt-injection phrase", _check_injection_phrase),
    Rule("imperative_directive_in_description", "high", "Tool description issues a meta-behavioral directive to the model", _check_imperative_phrase),
    Rule("unconstrained_path_or_command_param", "medium", "Free-text parameter where a constrained type would do", _check_unconstrained_param),
    Rule("long_description", "low", "Unusually long tool description", _check_long_description),
]


def classify_tool(tool: dict) -> tuple[str, list[str]]:
    """Static severity for a tool definition, from its name/description/schema alone."""
    worst, reasons = "low", []
    for rule in RULES:
        detail = rule.check(tool)
        if detail:
            reasons.append(f"{rule.id}: {detail}")
            if SEVERITY_RANK[rule.severity] > SEVERITY_RANK[worst]:
                worst = rule.severity
    return worst, reasons


def classify_tools(tools: list[dict]) -> dict[str, tuple[str, list[str]]]:
    return {tool["name"]: classify_tool(tool) for tool in tools}


# --- server-wide posture checks, run once at connect time --------------------

_UNTRUSTED_INPUT_KW = ("fetch", "browse", "web", "read_email", "read_issue", "read_pr", "search", "scrape", "rss", "read_url", "read_page")
_PRIVATE_DATA_KW = ("read_file", "read_db", "credential", "secret", "read_message", "contacts", "calendar", "sql_query", "read_repo", "env")
_EXFIL_KW = ("send_email", "http_post", "webhook", "publish", "write_file", "post_comment", "create_issue", "slack_post", "send_message", "upload", "http_request")


def _matches_any(text: str, keywords) -> bool:
    return _has_keyword(text, keywords) is not None


def check_lethal_trifecta(tools: list[dict]) -> Optional[str]:
    texts = [_text(t) for t in tools]
    has_input = any(_matches_any(t, _UNTRUSTED_INPUT_KW) for t in texts)
    has_private = any(_matches_any(t, _PRIVATE_DATA_KW) for t in texts)
    has_exfil = any(_matches_any(t, _EXFIL_KW) for t in texts)
    if has_input and has_private and has_exfil:
        return ("this server exposes untrusted-input, private-data, and external-communication "
                "tools together -- a single poisoned input can read private data and exfiltrate it")
    return None


_VERSION_PIN_RE = re.compile(r"@\d")


def check_unpinned_supply_chain(command: str, args: list[str]) -> Optional[str]:
    if command not in ("npx", "uvx", "pipx"):
        return None
    if any(_VERSION_PIN_RE.search(a) for a in args):
        return None
    return (f"launched via '{command}' with no version pin -- the package can change "
            "(\"rug pull\") after you've reviewed it, without this command changing")


_SECRET_KEY_HINTS = ("TOKEN", "KEY", "SECRET", "PASSWORD", "CREDENTIAL")


def check_plaintext_secrets(env: dict) -> list[str]:
    return [
        f"env var '{key}' looks like a credential passed in plaintext"
        for key, value in (env or {}).items()
        if value and not value.startswith("$") and any(hint in key.upper() for hint in _SECRET_KEY_HINTS)
    ]


# --- call-time payload checks, run on every tools/call ------------------------

_PATH_TRAVERSAL_RE = re.compile(r"\.\.[\\/]")
_SENSITIVE_PATH_HINTS = (".ssh", ".aws/credentials", "/etc/passwd", "/etc/shadow", "system32", ".env", "id_rsa")
_INTERNAL_HOSTNAMES = ("localhost", "metadata.google.internal", "metadata")
_EXEC_HINTS = ("exec", "eval", "shell", "subprocess", "command", "cmd")
_SHELL_METACHARS = (";", "&&", "|", "`", "$(")
_SECRET_VALUE_RE = re.compile(r"(sk-|ghp_|gho_|AKIA|xox[baprs]-)[A-Za-z0-9_\-]{10,}")


def _is_private_or_local_host(host: str) -> bool:
    host = host.lower().rstrip(".")  # resolvers ignore a trailing dot: 127.0.0.1. is 127.0.0.1
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        try:
            # URL parsers also accept short, decimal, hex and octal IPv4 forms: 127.1, 2852039166, 0x7f000001.
            ip = ipaddress.ip_address(socket.inet_aton(host))
        except (OSError, ValueError):  # ValueError: an embedded null byte
            return host in _INTERNAL_HOSTNAMES
    return ip.is_private or ip.is_loopback or ip.is_link_local


def _iter_string_leaves(value, path=""):
    """Walk nested dict/list argument values -- a malicious path or URL can
    arrive as {"options": {"path": "../../etc/passwd"}} just as easily as a
    top-level argument, and a scan of top-level values only would miss it."""
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, dict):
        for key, sub in value.items():
            yield from _iter_string_leaves(sub, f"{path}.{key}" if path else key)
    elif isinstance(value, list):
        for i, sub in enumerate(value):
            yield from _iter_string_leaves(sub, f"{path}[{i}]")


def check_payload(tool_name: str, description: str, arguments: dict) -> list[str]:
    flags = []
    text_lower = f"{tool_name} {description or ''}".lower()
    is_exec_tool = _matches_any(text_lower, _EXEC_HINTS)
    is_exfil_tool = _matches_any(text_lower, _EXFIL_KW)

    for key, value in _iter_string_leaves(arguments or {}):
        as_path = value.lower().replace("\\", "/")  # Windows paths: C:\Users\me\.aws\credentials
        if _PATH_TRAVERSAL_RE.search(value) or any(hint in as_path for hint in _SENSITIVE_PATH_HINTS):
            flags.append(f"argument '{key}' looks like a path-traversal/sensitive-path attempt: {value!r}")

        if "://" in value:
            try:
                host = urlsplit(value).hostname
            except ValueError:
                flags.append(f"argument '{key}' is a URL that can't be parsed, so its host can't be checked")
                continue
            if host and _is_private_or_local_host(host):
                flags.append(f"argument '{key}' targets a private/internal host ({host}) -- possible SSRF")

        if is_exec_tool and any(c in value for c in _SHELL_METACHARS):
            flags.append(f"argument '{key}' contains shell metacharacters passed to an exec-like tool: {value!r}")

        if is_exfil_tool and _SECRET_VALUE_RE.search(value):
            flags.append(f"argument '{key}' looks like a credential being sent through an external-communication tool")

    return flags


def decide(static_severity: str, payload_flags: list[str], block_severity: str) -> tuple[str, str]:
    """(decision, reason) for a single tools/call. Payload flags always block --
    they're evaluated at the moment of the call, not a guess about intent."""
    if payload_flags:
        return "block", "; ".join(payload_flags)
    if SEVERITY_RANK[static_severity] >= SEVERITY_RANK[block_severity]:
        return "block", f"tool statically flagged '{static_severity}'"
    return "allow", ""
