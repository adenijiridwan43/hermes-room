"""Deterministic sanitizer for untrusted Hermes tool output."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

_BIDI_AND_MARKS = {
    *range(0x200B, 0x2010),
    *range(0x202A, 0x202F),
    *range(0x2066, 0x206A),
    0x061C,
    0x180E,
    0xFEFF,
}
_C0_KEEP = {"\n", "\t", "\r"}

ANSI_RE = re.compile(r"\x1b(?:\[[0-9;?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\)|[@-Z\\^-_])")
HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.S | re.I)
SCRIPT_STYLE_RE = re.compile(r"<(script|style)\b[^>]*>.*?</\1>", re.S | re.I)
HIDDEN_NODE_RE = re.compile(
    r"<(div|span|p|section|article|td|li)\b[^>]*(?:"
    r"display\s*:\s*none|visibility\s*:\s*hidden|"
    r"aria-hidden\s*=\s*['\"]?true['\"]?|\shidden\b"
    r")[^>]*>.*?</\1>",
    re.S | re.I,
)
INSTRUCTION_PATTERNS = [
    ("instruction_ignore", re.compile(r"(?is)ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?")),
    ("instruction_developer_mode", re.compile(r"(?is)developer\s+mode")),
    ("instruction_exfiltrate", re.compile(r"(?is)exfiltrat\w*")),
    ("instruction_private_keys", re.compile(r"(?is)(?:private|ssh)\s+keys?")),
    ("instruction_curl_pipe", re.compile(r"(?is)curl\s+[^\n|]{0,200}\|\s*(?:sh|bash)")),
    ("instruction_send_contents", re.compile(r"(?is)send\s+(?:the\s+)?contents\s+of")),
    ("instruction_system_prompt", re.compile(r"(?is)(?:show|reveal|print)\s+(?:the\s+)?system\s+prompt")),
]
DOMAIN_RE = re.compile(r"(?:[a-z0-9-]+\.)+[a-z]{2,}", re.I)
MARKDOWN_LINK_RE = re.compile(r"\[([^\]]{1,240})\]\((https?://[^)\s]+)\)")
URL_RE = re.compile(r"https?://[^\s<>'\")]+", re.I)
PRIVATE_KEY_BLOCK_RE = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----.*?-----END (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----",
    re.S | re.I,
)
SECRET_PATTERNS = [
    ("secret_aws_access_key", re.compile(r"(?i)\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("secret_aws_secret_key", re.compile(r"(?i)aws(?:_| )?secret(?:_| )?access(?:_| )?key\s*[=:]\s*[\"']?[A-Za-z0-9/+=]{40}")),
    ("secret_github_token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b")),
    ("secret_github_pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b")),
    ("secret_gitlab_token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b")),
    ("secret_slack_token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("secret_openai_key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")),
    ("secret_google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("secret_jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("secret_generic_assignment", re.compile(
        r"(?i)(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?token|client[_-]?secret)"
        r"\s*[=:]\s*[\"']?[A-Za-z0-9_\-./+=]{12,}[\"']?"
    )),
]


@dataclass
class SanitizerResult:
    cleaned: str
    original_sha256: str
    changed: bool
    risk: str
    removed: dict[str, int] = field(default_factory=dict)
    rules: list[str] = field(default_factory=list)
    host: str | None = None
    source: str = "unknown"


def classify_source(tool_name: str | None) -> str:
    name = (tool_name or "").lower()
    if any(part in name for part in ("web", "browser", "fetch", "extract")):
        return "web"
    if "mail" in name or "email" in name or "imap" in name:
        return "email"
    if any(part in name for part in ("read_file", "file", "open")):
        return "file"
    if any(part in name for part in ("terminal", "shell", "command", "exec")):
        return "terminal"
    if "mcp" in name:
        return "mcp"
    return "tool"


def _host_from_args(args) -> str | None:
    if args is None:
        return None
    if not isinstance(args, dict):
        args = {"value": str(args)}
    for value in args.values():
        if not isinstance(value, str):
            continue
        for match in URL_RE.finditer(value):
            host = urlparse(match.group(0)).hostname
            if host:
                return host.lower()
    return None


def _host_from_text(text: str) -> str | None:
    match = URL_RE.search(text)
    if not match:
        return None
    host = urlparse(match.group(0)).hostname
    return host.lower() if host else None


def _strip_controls(text: str) -> tuple[str, dict[str, int]]:
    counts = {"zero_width": 0, "control": 0}
    out = []
    for ch in text:
        code = ord(ch)
        if code in _BIDI_AND_MARKS:
            counts["zero_width"] += 1
            continue
        if (code < 0x20 or code == 0x7F) and ch not in _C0_KEEP:
            counts["control"] += 1
            continue
        out.append(ch)
    return "".join(out), counts


def _sub_count(pattern: re.Pattern[str], repl: str, text: str) -> tuple[str, int]:
    matches = len(pattern.findall(text))
    return pattern.sub(repl, text), matches


def _annotate_links(text: str) -> tuple[str, int]:
    count = 0

    def repl(match: re.Match[str]) -> str:
        nonlocal count
        label, url = match.group(1), match.group(2)
        label_domains = DOMAIN_RE.findall(label)
        url_host = urlparse(url).hostname or ""
        if label_domains and url_host:
            if label_domains[0].lower() not in url_host.lower():
                count += 1
                return f"{label} [link→{url_host.lower()}]({url})"
        return match.group(0)

    return MARKDOWN_LINK_RE.sub(repl, text), count


def sanitize_text(text: str, tool_name: str | None = None, args: dict | None = None) -> SanitizerResult:
    if not isinstance(text, str):
        text = str(text)

    original = text
    original_sha256 = hashlib.sha256(original.encode("utf-8")).hexdigest()
    source = classify_source(tool_name)
    host = _host_from_args(args) or _host_from_text(original)

    removed: dict[str, int] = {}
    rules: list[str] = []

    def note(key: str, count: int, rule: str) -> None:
        if count:
            removed[key] = removed.get(key, 0) + count
            if rule not in rules:
                rules.append(rule)

    text, n = _sub_count(ANSI_RE, "[ansi removed]", text)
    note("ansi_escapes", n, "ansi_escape")

    text, counts = _strip_controls(text)
    note("zero_width", counts["zero_width"], "zero_width")
    note("control_chars", counts["control"], "control_char")

    text, n = _sub_count(SCRIPT_STYLE_RE, "[script/style removed]", text)
    note("script_style", n, "script_style")

    text, n = _sub_count(HTML_COMMENT_RE, "[hidden HTML comment removed]", text)
    note("html_comments", n, "html_comment")

    text, n = _sub_count(HIDDEN_NODE_RE, "[hidden element removed]", text)
    note("hidden_elements", n, "hidden_element")

    text, n = _sub_count(PRIVATE_KEY_BLOCK_RE, "[private key block removed]", text)
    note("private_key_block", n, "secret_private_key")

    for rule, pattern in SECRET_PATTERNS:
        text, n = _sub_count(pattern, "[secret masked]", text)
        note(rule, n, rule)

    for rule, pattern in INSTRUCTION_PATTERNS:
        text, n = _sub_count(pattern, "[untrusted instruction removed]", text)
        note(rule, n, rule)

    text, n = _annotate_links(text)
    note("link_mismatch", n, "link_mismatch")

    changed = bool(removed)
    high_rules = {
        "instruction_ignore",
        "instruction_developer_mode",
        "instruction_exfiltrate",
        "instruction_private_keys",
        "instruction_curl_pipe",
        "instruction_send_contents",
        "instruction_system_prompt",
        "hidden_element",
        "html_comment",
        "script_style",
        "secret_aws_access_key",
        "secret_aws_secret_key",
        "secret_github_token",
        "secret_github_pat",
        "secret_gitlab_token",
        "secret_slack_token",
        "secret_openai_key",
        "secret_google_api_key",
        "secret_jwt",
        "secret_generic_assignment",
        "secret_private_key",
    }
    if high_rules.intersection(rules):
        risk = "high"
    elif "link_mismatch" in rules or "ansi_escape" in rules:
        risk = "medium"
    elif changed:
        risk = "low"
    else:
        risk = "none"

    if changed:
        summary = ",".join(f"{k}({v})" for k, v in sorted(removed.items()))
        header = f"[UNTRUSTED source={source} host={host or '-'} risk={risk} removed={summary} hash={original_sha256[:12]}]\n"
        cleaned = header + text
    else:
        cleaned = text

    return SanitizerResult(
        cleaned=cleaned,
        original_sha256=original_sha256,
        changed=changed,
        risk=risk,
        removed=removed,
        rules=rules,
        host=host,
        source=source,
    )
