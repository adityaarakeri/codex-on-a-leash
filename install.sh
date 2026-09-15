#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COLOR=true
GLOBAL=false
DRY_RUN=false
UNINSTALL=false

red() { $COLOR && printf '\033[31m%s\033[0m\n' "$1" || printf '%s\n' "$1"; }
green() { $COLOR && printf '\033[32m%s\033[0m\n' "$1" || printf '%s\n' "$1"; }
yellow() { $COLOR && printf '\033[33m%s\033[0m\n' "$1" || printf '%s\n' "$1"; }
blue() { $COLOR && printf '\033[34m%s\033[0m\n' "$1" || printf '%s\n' "$1"; }

die() {
  red "$1"
  exit 1
}

usage() {
  cat <<USAGE
Usage: bash install.sh [options]

Options:
  --global       Install into ~/.codex instead of ./.codex
  --dry-run      Print actions without writing files
  --uninstall    Remove files previously installed by this script
  --no-color     Disable ANSI colors
  -h, --help     Show this help
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --global) GLOBAL=true ;;
    --dry-run) DRY_RUN=true ;;
    --uninstall) UNINSTALL=true ;;
    --no-color) COLOR=false ;;
    -h|--help) usage; exit 0 ;;
    *) die "Unknown option: $1" ;;
  esac
  shift
done

if ! command -v python3 >/dev/null 2>&1; then
  die "python3 is required"
fi

OS_NAME="$(uname -s || true)"
if [[ "$OS_NAME" == MINGW* || "$OS_NAME" == CYGWIN* || "$OS_NAME" == MSYS* || "${OS:-}" == "Windows_NT" ]]; then
  yellow "Codex hooks are not currently supported on native Windows. Install skipped."
  exit 1
fi

if $GLOBAL; then
  TARGET_ROOT="${HOME}/.codex"
else
  TARGET_ROOT="$(pwd)/.codex"
fi

SOURCE_ROOT="${SCRIPT_DIR}/.codex"
SOURCE_HOOKS_DIR="${SOURCE_ROOT}/hooks"
SOURCE_HOOKS_TEMPLATE="${SCRIPT_DIR}/hooks.template.json"
TARGET_HOOKS_DIR="${TARGET_ROOT}/hooks"
TARGET_CONFIG="${TARGET_ROOT}/config.toml"
TARGET_HOOKS_JSON="${TARGET_ROOT}/hooks.json"

log() { blue "==> $1"; }

run() {
  if $DRY_RUN; then
    printf '[dry-run] %s\n' "$*"
  else
    "$@"
  fi
}

append_gitignore() {
  local gitignore_file="$(pwd)/.gitignore"
  local line=".codex/command-audit.log"

  $GLOBAL && return 0

  if [[ -f "$gitignore_file" ]] && grep -qxF "$line" "$gitignore_file"; then
    return 0
  fi

  if $DRY_RUN; then
    printf '[dry-run] append %s to %s\n' "$line" "$gitignore_file"
  else
    touch "$gitignore_file"
    printf '\n%s\n' "$line" >> "$gitignore_file"
  fi
}

write_config() {
  local desired='[features]\nhooks = true\n'
  if $DRY_RUN; then
    printf '[dry-run] write %s\n' "$TARGET_CONFIG"
    return 0
  fi

  mkdir -p "$TARGET_ROOT"
  if [[ ! -f "$TARGET_CONFIG" ]]; then
    printf '%b' "$desired" > "$TARGET_CONFIG"
    return 0
  fi

  if grep -q '^\[features\]' "$TARGET_CONFIG"; then
    python3 - "$TARGET_CONFIG" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
lines = text.splitlines()
out = []
in_features = False
inserted = False
for line in lines:
    if in_features and line.strip().split("=", 1)[0].strip() in {"hooks", "codex_hooks"}:
        if not inserted:
            out.append("hooks = true")
            inserted = True
        continue
    out.append(line)
    if line.strip() == "[features]":
        in_features = True
        continue
    if in_features and line.startswith("[") and line.strip() != "[features]" and not inserted:
        out.insert(len(out)-1, "hooks = true")
        inserted = True
        in_features = False
if in_features and not inserted:
    out.append("hooks = true")
    inserted = True
path.write_text("\n".join(out) + "\n", encoding="utf-8")
PY
  else
    printf '\n[features]\nhooks = true\n' >> "$TARGET_CONFIG"
  fi
}

write_hooks_json() {
  local hook_root
  hook_root="$(python3 - "$TARGET_HOOKS_DIR" <<'PY'
from pathlib import Path
import sys

print(Path(sys.argv[1]).resolve())
PY
)"

  if $DRY_RUN; then
    printf '[dry-run] render %s with hook root %s\n' "$TARGET_HOOKS_JSON" "$hook_root"
    return 0
  fi

  python3 - "$SOURCE_HOOKS_TEMPLATE" "$TARGET_HOOKS_JSON" "$hook_root" <<'PY'
import json
from pathlib import Path
import shlex
import sys

template_path = Path(sys.argv[1])
target = Path(sys.argv[2])
hook_root = Path(sys.argv[3])

template = json.loads(template_path.read_text(encoding="utf-8"))
if target.exists():
    existing = json.loads(target.read_text(encoding="utf-8"))
else:
    existing = {}

owned_names = {
    "bash_audit.py", "bash_guard.py", "prompt_guard.py",
    "session_bootstrap.py", "shared.py", "stop_validator.py", "tool_guard.py",
}

def is_owned(hook):
    command = hook.get("command", "").replace("\\", "/").rstrip("\\\"'")
    return any(command.endswith("/" + name) for name in owned_names)

merged = dict(existing)
merged_hooks = dict(existing.get("hooks", {}))
for event, groups in template.get("hooks", {}).items():
    kept_groups = []
    for group in merged_hooks.get(event, []):
        kept_hooks = [hook for hook in group.get("hooks", []) if not is_owned(hook)]
        if kept_hooks:
            kept_group = dict(group)
            kept_group["hooks"] = kept_hooks
            kept_groups.append(kept_group)
    def render(value):
        if isinstance(value, str) and "REPLACE_HOOK_ROOT/" in value:
            suffix = value.split("REPLACE_HOOK_ROOT/", 1)[1]
            return value.replace(
                "REPLACE_HOOK_ROOT/" + suffix,
                shlex.quote(str(hook_root / suffix)),
            )
        if isinstance(value, list):
            return [render(item) for item in value]
        if isinstance(value, dict):
            return {key: render(item) for key, item in value.items()}
        return value

    rendered_groups = render(groups)
    merged_hooks[event] = kept_groups + rendered_groups
merged["hooks"] = merged_hooks
target.parent.mkdir(parents=True, exist_ok=True)
target.write_text(json.dumps(merged, indent=2) + "\n", encoding="utf-8")
PY
}

install_files() {
  log "Installing hooks into ${TARGET_ROOT}"
  if $DRY_RUN; then
    printf '[dry-run] mkdir -p %q\n' "$TARGET_HOOKS_DIR"
  else
    mkdir -p "$TARGET_HOOKS_DIR"
  fi
  if [[ "$(cd "$SOURCE_HOOKS_DIR" && pwd -P)" != "$(cd "$TARGET_HOOKS_DIR" 2>/dev/null && pwd -P)" ]]; then
    if $DRY_RUN; then
      printf '[dry-run] copy hooks from %s to %s\n' "$SOURCE_HOOKS_DIR" "$TARGET_HOOKS_DIR"
    else
      cp "$SOURCE_HOOKS_DIR"/*.py "$TARGET_HOOKS_DIR/"
    fi
  fi
  if ! $DRY_RUN; then
    chmod 755 "$TARGET_HOOKS_DIR"/*.py
  fi
  write_config
  write_hooks_json
  append_gitignore
  green "Installed codex-on-a-leash into ${TARGET_ROOT}"
}

uninstall_files() {
  log "Removing hooks from ${TARGET_ROOT}"
  if $DRY_RUN; then
    printf '[dry-run] rm -rf %q\n' "$TARGET_HOOKS_DIR"
    printf '[dry-run] rm -f %q %q\n' "$TARGET_HOOKS_JSON" "$TARGET_CONFIG"
    return 0
  fi
  python3 - "$TARGET_HOOKS_JSON" <<'PY'
import json
from pathlib import Path
import sys

path = Path(sys.argv[1])
owned_names = {
    "bash_audit.py", "bash_guard.py", "prompt_guard.py",
    "session_bootstrap.py", "shared.py", "stop_validator.py", "tool_guard.py",
}
if path.exists():
    data = json.loads(path.read_text(encoding="utf-8"))
    hooks = data.get("hooks", {})
    for event, groups in list(hooks.items()):
        kept_groups = []
        for group in groups:
            kept_hooks = [
                hook for hook in group.get("hooks", [])
                if not any(
                    hook.get("command", "").replace("\\", "/").rstrip("\\\"'").endswith("/" + name)
                    for name in owned_names
                )
            ]
            if kept_hooks:
                kept_group = dict(group)
                kept_group["hooks"] = kept_hooks
                kept_groups.append(kept_group)
        if kept_groups:
            hooks[event] = kept_groups
        else:
            del hooks[event]
    if hooks:
        data["hooks"] = hooks
    else:
        data.pop("hooks", None)
    if data:
        path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    else:
        path.unlink()
PY
  for hook in "$TARGET_HOOKS_DIR"/*.py; do
    [[ -e "$hook" ]] || continue
    case "$(basename "$hook")" in
      bash_audit.py|bash_guard.py|prompt_guard.py|session_bootstrap.py|shared.py|stop_validator.py|tool_guard.py)
        rm -f "$hook"
        ;;
    esac
  done
  rmdir "$TARGET_HOOKS_DIR" 2>/dev/null || true
  if [[ -f "$TARGET_CONFIG" ]]; then
    python3 - "$TARGET_CONFIG" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
lines = path.read_text(encoding="utf-8").splitlines()
out = [
    line for line in lines
    if line.strip() not in {"hooks = true", "codex_hooks = true"}
]
while out and not out[-1].strip():
    out.pop()
if out and out[-1].strip() == "[features]":
    out.pop()
while out and not out[-1].strip():
    out.pop()
if out:
    path.write_text("\n".join(out) + "\n", encoding="utf-8")
else:
    path.unlink()
PY
  fi
  green "Removed codex-on-a-leash from ${TARGET_ROOT}"
}

if $UNINSTALL; then
  uninstall_files
else
  install_files
fi
