#!/usr/bin/env python3
from __future__ import annotations

import re
import shlex

from shared import add_context, pretool_deny, read_stdin_json

BLOCK_PATTERNS = [
    ("rm-root", r"\brm\s+-[^|;&\n]*\brf\b\s+(/\s*|~\s*|/\*|\.\.)"),
    ("mkfs", r"\bmkfs(\.|\s)"),
    ("shred-system", r"\bshred\b.+(/etc|/usr|/bin|/boot|/var|/dev)"),
    ("dd-device", r"\bdd\b.+\bof=/dev/"),
    ("sudoers-write", r"(/etc/sudoers|/etc/sudoers\.d)"),
    ("authorized-keys", r"authorized_keys"),
    ("cron-persistence", r"(/etc/cron\.|crontab\s+-e|crontab\s+-r)"),
    ("systemd-persistence", r"/etc/systemd/system|systemctl\s+enable"),
    (
        "reverse-shell",
        r"(/dev/tcp/|nc\s+-e\s+|bash\s+-i\s+>&|python[23]?\s+-c\s+['\"].*socket)",
    ),
    ("curl-pipe-shell", r"\b(curl|wget)\b[^\n|]*\|\s*(bash|sh|zsh)\b"),
    ("eval-curl", r"eval\s+\$\((curl|wget)"),
    (
        "env-exfiltration",
        r"\b(env|printenv|cat\s+\.env|cat\s+~/.aws/credentials).*(curl|nc|scp|rsync|ftp)",
    ),
    ("metadata-access", r"169\.254\.169\.254|metadata\.google\.internal"),
    ("chmod-system", r"\bchmod\b\s+777\s+(/etc|/usr|/bin|/root)"),
    ("reboot", r"\b(shutdown|reboot|poweroff|halt|init\s+0)\b"),
]

WARN_PATTERNS = [
    (
        "network-installer",
        r"^(?:sudo\s+)?(?:curl|wget)\b[^;&|]*(?:install|setup|bootstrap)",
    ),
    (
        "package-manager-system",
        r"^(?:sudo\s+)?(?:apt|yum|dnf|pacman|brew)\s+(?:install|upgrade|remove)\b",
    ),
]


def normalize(command: str) -> str:
    return " ".join(command.strip().split())


def command_tokens(command: str) -> list[str]:
    try:
        return shlex.split(command)
    except ValueError:
        return []


def wrapped_commands(tokens: list[str]) -> list[list[str]]:
    commands = [tokens]
    for index, token in enumerate(tokens[:-1]):
        if token in {"-c", "--command"}:
            nested = command_tokens(tokens[index + 1])
            if nested:
                commands.extend(wrapped_commands(nested))
    return commands


def detects_root_removal(tokens: list[str]) -> bool:
    for index, token in enumerate(tokens):
        if token != "rm":
            continue
        recursive = False
        force = False
        paths: list[str] = []
        for argument in tokens[index + 1:]:
            if argument == "--":
                paths.extend(tokens[index + 2:])
                break
            if argument.startswith("--"):
                recursive |= argument == "--recursive"
                force |= argument == "--force"
                continue
            if argument.startswith("-") and argument != "-":
                recursive |= "r" in argument or "R" in argument
                force |= "f" in argument
                continue
            paths.append(argument)
        if recursive and force and any(path in {"/", "~", "/*", ".."} for path in paths):
            return True
    return False


def detects_protected_force_push(tokens: list[str]) -> bool:
    for index in range(len(tokens) - 1):
        if tokens[index:index + 2] != ["git", "push"]:
            continue
        push_args = tokens[index + 2:]
        if not any(argument in {"-f", "--force"} for argument in push_args):
            continue
        if any(argument in {"main", "master", "production"} for argument in push_args):
            return True
    return False


def main() -> None:
    payload = read_stdin_json()
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):
        tool_input = {}
    command_value = tool_input.get("command")
    command = command_value if isinstance(command_value, str) else ""
    cmd = normalize(command)

    tokenized_commands = wrapped_commands(command_tokens(command))
    if any(detects_root_removal(tokens) for tokens in tokenized_commands):
        pretool_deny(
            "Blocked by codex-on-a-leash bash guard: 'rm-root' matched for command: "
            f"{cmd}"
        )
    if any(detects_protected_force_push(tokens) for tokens in tokenized_commands):
        pretool_deny(
            "Blocked by codex-on-a-leash bash guard: 'force-push-protected' matched for command: "
            f"{cmd}"
        )

    for label, pattern in BLOCK_PATTERNS:
        if re.search(pattern, cmd, flags=re.IGNORECASE):
            pretool_deny(
                "Blocked by codex-on-a-leash bash guard: "
                f"'{label}' matched for command: {cmd}"
            )

    warning_hits = [
        label
        for label, pattern in WARN_PATTERNS
        if re.search(pattern, cmd, flags=re.IGNORECASE)
    ]
    if warning_hits:
        add_context(
            "PreToolUse",
            "Review this command before proceeding: "
            + ", ".join(warning_hits)
            + " detected. Confirm the source and scope, and inspect any installer "
            "script before executing it.",
        )


if __name__ == "__main__":
    main()
