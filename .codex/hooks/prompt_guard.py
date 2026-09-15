#!/usr/bin/env python3
from __future__ import annotations

import re

from shared import block, continue_ok, read_stdin_json

INJECTION_PATTERNS = [
    (
        "ignore-and-reveal",
        r"ignore (all )?(previous|prior) instructions.{0,100}"
        r"(show|reveal|print|give|output).{0,40}(system|hidden|developer)\s+prompt",
    ),
    (
        "developer-mode-bypass",
        r"developer mode.{0,80}(jailbreak|bypass|disable|ignore|reveal|system prompt)",
    ),
    (
        "bypass-guardrails",
        r"(bypass|disable|ignore).{0,30}(all )?(safety|policy|guardrails|approval|sandbox|hook)",
    ),
    (
        "support-told-me",
        r"(openai|security|support)\s+(told|asked|authorized)\s+me.{0,60}"
        r"(reveal|ignore|bypass|disable|secret|password|token)",
    ),
]

SECRET_PATTERNS = [
    ("openai-key", r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    ("github-token", r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    ("slack-token", r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    ("aws-access-key", r"\bAKIA[0-9A-Z]{16}\b"),
    ("pem-private-key", r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
]


def main() -> None:
    payload = read_stdin_json()
    prompt_value = payload.get("prompt")
    prompt = prompt_value if isinstance(prompt_value, str) else ""

    lowered = prompt.lower()

    for label, pattern in INJECTION_PATTERNS:
        if re.search(pattern, lowered, flags=re.IGNORECASE | re.MULTILINE):
            block(
                "Blocked by codex-on-a-leash prompt guard: "
                f"detected risky prompt pattern '{label}'."
            )

    for label, pattern in SECRET_PATTERNS:
        if re.search(pattern, prompt, flags=re.MULTILINE):
            block(
                "Blocked by codex-on-a-leash prompt guard: "
                f"detected inline secret pattern '{label}'."
            )

    continue_ok()


if __name__ == "__main__":
    main()
