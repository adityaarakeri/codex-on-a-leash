#!/usr/bin/env python3
from __future__ import annotations

import re

from shared import continue_ok, continue_turn, read_stdin_json

SHOULD_CONTINUE_PATTERNS = [
    (
        r"\b(?:i|we)\s+(?:have\s+)?"
        r"(?:changed|updated|implemented|fixed|refactored|patched|added|created|wrote|modified|removed)\b"
    ),
    r"^\s*(?:added|created|wrote|modified|removed)\b",
    r"\b(?:i|we)\s+(?:am|have\s+)?(?:done|completed|finished)\b",
]

VERIFICATION_PATTERNS = [
    r"\b(test|pytest|verified|validation|lint|build|checked|ran)\b",
    r"\bnot run|unable to run|could not run\b",
]


def main() -> None:
    payload = read_stdin_json()
    if payload.get("stop_hook_active") is True:
        continue_ok()

    message_value = payload.get("last_assistant_message")
    last_message = message_value if isinstance(message_value, str) else ""
    if not last_message.strip():
        continue_ok()

    suggests_changes = any(
        re.search(p, last_message, flags=re.IGNORECASE) for p in SHOULD_CONTINUE_PATTERNS
    )
    mentions_validation = any(
        re.search(p, last_message, flags=re.IGNORECASE) for p in VERIFICATION_PATTERNS
    )

    if suggests_changes and not mentions_validation:
        continue_turn(
            "Before you stop, do one more pass: verify the work, mention what you "
            "validated, and call out anything you could not test."
        )

    continue_ok()


if __name__ == "__main__":
    main()
