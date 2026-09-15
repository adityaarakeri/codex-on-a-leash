#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


def check_repository(root: Path) -> list[str]:
    errors: list[str] = []
    config_path = root / ".codex" / "config.toml"
    hooks_path = root / ".codex" / "hooks.json"
    project_path = root / "pyproject.toml"
    readme_path = root / "README.md"
    metadata_path = root / "codex_on_a_leash.egg-info" / "PKG-INFO"

    config = config_path.read_text(encoding="utf-8")
    feature_table = re.search(r"(?ms)^\[features\]\s*\n(.*?)(?=^\[|\Z)", config)
    if feature_table is None:
        errors.append(".codex/config.toml is missing the [features] table")
    else:
        feature_lines = feature_table.group(1)
        if re.search(r"(?m)^\s*codex_hooks\s*=", feature_lines):
            errors.append(".codex/config.toml uses deprecated features.codex_hooks")
        if not re.search(r"(?m)^\s*hooks\s*=\s*true\s*(?:#.*)?$", feature_lines):
            errors.append(".codex/config.toml must enable hooks with features.hooks = true")

    hooks_text = hooks_path.read_text(encoding="utf-8")
    try:
        json.loads(hooks_text)
    except json.JSONDecodeError as exc:
        errors.append(f".codex/hooks.json is invalid JSON: {exc}")
    if "REPLACE_HOOK_ROOT" in hooks_text:
        errors.append(".codex/hooks.json contains an unresolved REPLACE_HOOK_ROOT template")

    project = project_path.read_text(encoding="utf-8")
    project_name = re.search(r'(?m)^name\s*=\s*"([^"]+)"', project)
    project_version = re.search(r'(?m)^version\s*=\s*"([^"]+)"', project)
    if project_name is None or project_version is None:
        errors.append("pyproject.toml must declare a static project name and version")
        return errors

    metadata = metadata_path.read_text(encoding="utf-8")
    metadata_name = re.search(r"(?m)^Name:\s*(.+)$", metadata)
    metadata_version = re.search(r"(?m)^Version:\s*(.+)$", metadata)
    if metadata_name is None or metadata_name.group(1) != project_name.group(1):
        errors.append("PKG-INFO Name does not match pyproject.toml project.name")
    if metadata_version is None or metadata_version.group(1) != project_version.group(1):
        errors.append("PKG-INFO Version does not match pyproject.toml project.version")

    _, separator, description = metadata.partition("\n\n")
    readme = readme_path.read_text(encoding="utf-8")
    if not separator or description.rstrip("\n") != readme.rstrip("\n"):
        errors.append("PKG-INFO description is stale; regenerate metadata from README.md")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Check release metadata and active hook config")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()

    try:
        errors = check_repository(args.root.resolve())
    except OSError as exc:
        print(f"Release metadata check could not read a required file: {exc}", file=sys.stderr)
        return 1

    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1

    print("Release metadata and active hook configuration are consistent.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
