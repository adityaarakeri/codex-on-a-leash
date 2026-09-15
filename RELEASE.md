# codex-on-a-leash v0.1.0

`codex-on-a-leash` is a practical security guardrail layer for Codex hooks.

This release configures hooks for the following events and tool paths:

- `SessionStart`
- `UserPromptSubmit`
- `PreToolUse` for `Bash`, `apply_patch`, MCP, and selected local function tools
- `PermissionRequest` for `Bash`, `apply_patch`, MCP, and selected local function tools
- `PostToolUse` for `Bash`
- `Stop`

## Highlights

- blocks risky prompt requests and obvious inline secrets before the prompt is sent
- blocks destructive Bash commands and checks selected non-Bash inputs for sensitive data
- advises on direct network installers and system package changes
- records executed Bash commands to a local audit log
- injects repo-aware session guidance automatically
- nudges Codex to verify work before ending a turn
- supports project-local and global installation

Project-local hook definitions run only after the project `.codex/` layer and each current hook definition have been reviewed and trusted in Codex. Review the commands and scripts before trusting them.

## Why this exists

Codex can already do real work. That includes real shell access.

The problem is not that Codex is malicious. The problem is that software agents are incredibly willing, occasionally overconfident, and only one `curl | bash` away from teaching your terminal new forms of regret.

This repo gives you a deterministic, inspectable hook layer that is honest about current Codex capabilities.

## Known limits

- hook behavior can change between Codex releases; consult the current Codex hooks documentation when reviewing runtime compatibility
- selected non-Bash tool inputs are checked for sensitive paths and common credential patterns; coverage is matcher-based and is not comprehensive
- this project audits Bash only; it does not audit PostToolUse results for other tool families
- post-tool hooks cannot undo side effects from commands that already ran
- native Windows installation is not supported by this release. The installer requires Bash and writes Unix-style paths with `python3` hook commands; there is no PowerShell installer or `commandWindows` configuration. This is a project limitation, not a claim that Codex itself lacks Windows hook support.

## Upgrade notes

This is the first public release.
