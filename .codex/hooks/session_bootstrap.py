#!/usr/bin/env python3
from __future__ import annotations

from shared import add_context, file_exists_under, find_git_root, git_branch, read_stdin_json

SYSTEM_HINT = "codex-on-a-leash session policy loaded"


def main() -> None:
    payload = read_stdin_json()
    cwd_value = payload.get("cwd")
    cwd = cwd_value if isinstance(cwd_value, str) and cwd_value else "."
    root = find_git_root(cwd)
    branch = git_branch(cwd)

    agents_file = file_exists_under(root, "AGENTS.md", ".codex/AGENTS.md")
    readme_file = file_exists_under(root, "README.md")

    context_parts = [
        "codex-on-a-leash is active for this session.",
        f"Repo root: {root}",
        f"Branch: {branch}",
        "Use the least destructive path first.",
        "Prefer reading repo guidance before making edits.",
        "When shelling out, avoid persistence, secret access, network exfiltration, "
        "or unsafe git history changes.",
    ]

    if agents_file:
        context_parts.append(f"Repo guidance file detected: {agents_file}")
    if readme_file:
        context_parts.append(f"Project README detected: {readme_file}")

    add_context("SessionStart", " ".join(context_parts), system_message=SYSTEM_HINT)


if __name__ == "__main__":
    main()
