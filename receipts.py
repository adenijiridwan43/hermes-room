"""Local trust receipts for Hermes Room.

Receipts are JSONL in the plugin data dir. They store hashes and rule IDs,
never raw content by default.
"""

from __future__ import annotations

import json
import os
import time
import uuid
from pathlib import Path
from typing import Any


def data_dir() -> Path:
    home = os.environ.get("HERMES_HOME") or os.path.join(Path.home(), ".hermes")
    path = Path(home) / "hermes-room"
    path.mkdir(parents=True, exist_ok=True)
    return path


def receipts_path() -> Path:
    return data_dir() / "receipts.jsonl"


def save_receipt(receipt: dict[str, Any]) -> dict[str, Any]:
    receipt = dict(receipt)
    receipt.setdefault("id", uuid.uuid4().hex[:12])
    receipt.setdefault("created_at", int(time.time()))
    path = receipts_path()
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(receipt, ensure_ascii=False, sort_keys=True) + "\n")
    return receipt


def list_receipts(limit: int = 20) -> list[dict[str, Any]]:
    path = receipts_path()
    if not path.exists():
        return []
    try:
        limit = max(1, min(int(limit or 20), 500))
    except (TypeError, ValueError):
        limit = 20
    with path.open("r", encoding="utf-8") as handle:
        lines = handle.readlines()[-limit:]
    out = []
    for line in lines:
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return list(reversed(out))


def report_markdown(limit: int = 20) -> str:
    rows = list(reversed(list_receipts(limit)))
    if not rows:
        return "# Hermes Room Trust Report\n\nNo receipts recorded yet.\n"
    lines = [
        "# Hermes Room Trust Report",
        "",
        f"Receipts included: {len(rows)}",
        "",
        "| Tool | Source | Host | Risk | Removed | Original SHA-256 |",
        "|---|---|---|---|---|---|",
    ]
    for row in rows:
        removed = row.get("removed") or {}
        removed_txt = ", ".join(f"{k}({v})" for k, v in sorted(removed.items())) or "-"
        lines.append(
            "| {tool} | {source} | {host} | {risk} | {removed} | `{sha}` |".format(
                tool=row.get("tool_name", "?"),
                source=row.get("source", "?"),
                host=row.get("host") or "-",
                risk=row.get("risk", "?"),
                removed=removed_txt.replace("|", "\\|"),
                sha=str(row.get("original_sha256", ""))[:12],
            )
        )
    lines += [
        "",
        "Raw content is not stored by default. Receipts contain hashes, rule IDs and counts only.",
        "",
    ]
    return "\n".join(lines)
