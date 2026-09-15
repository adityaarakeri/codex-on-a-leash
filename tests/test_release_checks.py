from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / "scripts" / "check_release_metadata.py"


def copy_release_inputs(root: Path) -> None:
    for relative in (
        ".codex/config.toml",
        ".codex/hooks.json",
        "pyproject.toml",
        "README.md",
        "codex_on_a_leash.egg-info/PKG-INFO",
    ):
        source = ROOT / relative
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)


def run_checker(root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(CHECKER), "--root", str(root)],
        text=True,
        capture_output=True,
        check=False,
    )


def test_release_checker_accepts_current_repository_inputs(tmp_path: Path) -> None:
    copy_release_inputs(tmp_path)

    result = run_checker(tmp_path)

    assert result.returncode == 0, result.stderr
    assert "consistent" in result.stdout


def test_release_checker_rejects_deprecated_feature_key(tmp_path: Path) -> None:
    copy_release_inputs(tmp_path)
    config = tmp_path / ".codex" / "config.toml"
    config.write_text('[features]\ncodex_hooks = true\n', encoding="utf-8")

    result = run_checker(tmp_path)

    assert result.returncode != 0
    assert "deprecated features.codex_hooks" in result.stderr


def test_release_checker_rejects_unresolved_hook_template(tmp_path: Path) -> None:
    copy_release_inputs(tmp_path)
    hooks = tmp_path / ".codex" / "hooks.json"
    payload = json.loads(hooks.read_text(encoding="utf-8"))
    payload["template"] = "REPLACE_HOOK_ROOT"
    hooks.write_text(json.dumps(payload), encoding="utf-8")

    result = run_checker(tmp_path)

    assert result.returncode != 0
    assert "unresolved REPLACE_HOOK_ROOT" in result.stderr


def test_release_checker_rejects_stale_version_and_readme_metadata(tmp_path: Path) -> None:
    copy_release_inputs(tmp_path)
    metadata = tmp_path / "codex_on_a_leash.egg-info" / "PKG-INFO"
    contents = metadata.read_text(encoding="utf-8")
    contents = re.sub(r"(?m)^Version: .*", "Version: 9.9.9", contents, count=1)
    metadata.write_text(
        contents + "\nStale generated text.\n",
        encoding="utf-8",
    )

    result = run_checker(tmp_path)

    assert result.returncode != 0
    assert "PKG-INFO Version" in result.stderr
    assert "description is stale" in result.stderr
