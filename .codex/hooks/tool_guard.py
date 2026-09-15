#!/usr/bin/env python3
from __future__ import annotations

import json
import re

from shared import add_context, emit_json, pretool_deny, read_stdin_json

SENSITIVE_PATTERNS = (
    r"(?:^|[\\/\"'])\.env(?:$|[\\/\"'])",
    r"(?:^|[\\/])(?:id_rsa|authorized_keys|credentials)(?:$|[\\/])",
    r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
    r"\b(?:sk-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{20,})\b",
)


def main() -> None:
    payload = read_stdin_json()
    event = str(payload.get("hook_event_name") or "PreToolUse")
    tool_input = json.dumps(payload.get("tool_input", {}), ensure_ascii=False)
    if any(re.search(pattern, tool_input, flags=re.IGNORECASE) for pattern in SENSITIVE_PATTERNS):
        if event == "PermissionRequest":
            emit_json(
                {
                    "hookSpecificOutput": {
                        "hookEventName": "PermissionRequest",
                        "decision": {
                            "behavior": "deny",
                            "message": (
                                "Permission denied by codex-on-a-leash: "
                                "sensitive non-Bash input"
                            ),
                        },
                    }
                }
            )
            raise SystemExit(0)
        pretool_deny("Blocked by codex-on-a-leash: sensitive non-Bash input")

    if event == "PreToolUse":
        add_context(
            "PreToolUse",
            "Non-Bash tool input passed the codex-on-a-leash sensitive-data check.",
        )


if __name__ == "__main__":
    main()
