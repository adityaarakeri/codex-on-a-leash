#!/usr/bin/env bash
set -euo pipefail

VERSION="${1:-0.1.0}"

echo "Running release checks for v${VERSION}"
python3 scripts/check_release_metadata.py
python3 -m pip install -e .[dev]
ruff check .
pytest

git diff --quiet || {
  echo "Working tree is dirty. Commit changes before tagging."
  exit 1
}

git tag -a "v${VERSION}" -m "codex-on-a-leash v${VERSION}"
echo "Created tag v${VERSION}"
