#!/usr/bin/env python3
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from shared import (
    append_jsonl,
    find_git_root,
    read_stdin_json,
    redact_secrets,
    truncate_text,
    utc_now_iso,
)

RISK_FLAG_PATTERNS = [
    ("network", r"\b(curl|wget|scp|rsync|ssh|nc|ncat|telnet)\b"),
    ("delete", r"\b(rm|shred)\b"),
    ("privilege", r"\b(sudo|su)\b"),
    ("git-push", r"\bgit\s+push\b"),
    ("archive", r"\b(tar|zip|gzip)\b"),
]


def extract_response_text(tool_response: Any) -> str:
    if isinstance(tool_response, str):
        return tool_response
    if isinstance(tool_response, dict):
        for key in ("output", "stdout", "stderr", "text"):
            value = tool_response.get(key)
            if isinstance(value, str) and value.strip():
                return value
        return json.dumps(tool_response, ensure_ascii=False)
    return str(tool_response)


def main() -> None:
    payload = read_stdin_json()
    cwd_value = payload.get("cwd")
    cwd = cwd_value if isinstance(cwd_value, str) and cwd_value else "."
    git_root = find_git_root(cwd)
    log_path = Path(git_root) / ".codex" / "command-audit.log"

    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):
        tool_input = {}
    command_value = tool_input.get("command")
    command = redact_secrets(command_value if isinstance(command_value, str) else "")
    response_text = redact_secrets(extract_response_text(payload.get("tool_response")))
    risk_flags = [
        label
        for label, pattern in RISK_FLAG_PATTERNS
        if re.search(pattern, command, flags=re.IGNORECASE)
    ]

    record = {
        "ts": utc_now_iso(),
        "session_id": payload.get("session_id"),
        "turn_id": payload.get("turn_id"),
        "tool": payload.get("tool_name", "Bash"),
        "command": command,
        "cwd": cwd,
        "risk_flags": risk_flags,
        "response_excerpt": truncate_text(response_text, 400),
    }
    append_jsonl(log_path, record)


if __name__ == "__main__":
    main()
