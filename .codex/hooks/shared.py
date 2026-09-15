#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def read_stdin_json() -> dict[str, Any]:
    raw = sys.stdin.read().strip()
    if not raw:
        return {}
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        block(f"Invalid hook JSON input: {exc}")
        raise RuntimeError("unreachable")
    if not isinstance(payload, dict):
        block("Invalid hook JSON input: expected a JSON object")
    return payload


def emit_json(payload: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(payload, separators=(",", ":")))
    sys.stdout.flush()


def block(reason: str) -> None:
    emit_json({"decision": "block", "reason": reason})
    raise SystemExit(0)


def pretool_deny(reason: str, *, event_name: str = "PreToolUse") -> None:
    emit_json(
        {
            "hookSpecificOutput": {
                "hookEventName": event_name,
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            }
        }
    )
    raise SystemExit(0)


def add_context(event_name: str, text: str, *, system_message: str | None = None) -> None:
    payload: dict[str, Any] = {
        "hookSpecificOutput": {"hookEventName": event_name, "additionalContext": text}
    }
    if system_message:
        payload["systemMessage"] = system_message
    emit_json(payload)
    raise SystemExit(0)


def continue_turn(reason: str) -> None:
    emit_json({"decision": "block", "reason": reason})
    raise SystemExit(0)


def continue_ok() -> None:
    emit_json({"continue": True})
    raise SystemExit(0)


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def append_jsonl(path: Path, item: dict[str, Any]) -> None:
    ensure_parent(path)
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    os.chmod(path, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(item, ensure_ascii=False) + "\n")


REDACTION_PATTERNS = [
    (re.compile(r"(?i)(authorization\s*:\s*bearer\s+)[^\s,;]+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(https?://[^\s/@:]+:)[^\s/@]+(@)"), r"\1[REDACTED]\2"),
    (
        re.compile(
            r"(?i)(\b(?:api[_-]?key|token|secret|password|passwd|client_secret)"
            r"\s*[=:]\s*)[^\s,;&]+"
        ),
        r"\1[REDACTED]",
    ),
    (
        re.compile(
            r"\b(?:sk-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{20,}|"
            r"xox[baprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16})\b"
        ),
        "[REDACTED]",
    ),
    (
        re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]*?"
            r"-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"
        ),
        "[REDACTED PRIVATE KEY]",
    ),
]


def redact_secrets(text: str) -> str:
    for pattern, replacement in REDACTION_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def truncate_text(text: str, limit: int = 300) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def find_git_root(cwd: str | None = None) -> Path:
    start = Path(cwd or os.getcwd())
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=str(start),
            capture_output=True,
            text=True,
            check=True,
        )
        return Path(result.stdout.strip())
    except Exception:
        return start


def git_branch(cwd: str | None = None) -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=cwd,
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.strip()
    except Exception:
        return "unknown"


def file_exists_under(root: Path, *relative_paths: str) -> str | None:
    for rel in relative_paths:
        candidate = root / rel
        if candidate.exists():
            return rel
    return None


def regex_hits(text: str, patterns: list[tuple[str, str]]) -> list[str]:
    hits: list[str] = []
    for label, pattern in patterns:
        if re.search(pattern, text, flags=re.IGNORECASE | re.MULTILINE):
            hits.append(label)
    return hits
