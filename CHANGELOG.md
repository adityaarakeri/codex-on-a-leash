# Changelog

All notable changes to this project will be documented in this file.

The format is inspired by Keep a Changelog and this project follows Semantic Versioning.

## [Unreleased]

### Added
- guard checks for selected `apply_patch`, MCP, and local function tool inputs
- `PermissionRequest` checks for sensitive input
- model-visible warnings for direct network installers and system package changes

### Changed
- session policy now loads after startup, resume, clear, and compact events
- Stop checks recognize common change summaries and avoid treating informational dates as file changes
- hook fixtures, malformed-payload coverage, and project trust guidance reflect the current Codex hooks contract

## [0.1.0] - 2026-04-05

### Added
- initial Codex-native hook suite for `SessionStart`, `UserPromptSubmit`, `PreToolUse:Bash`, `PostToolUse:Bash`, and `Stop`
- project-local and global installer with dry-run and uninstall support
- prompt scanning for common prompt injection phrases and obvious inline secrets
- Bash command blocking for destructive, persistence, exfiltration, and pipe-to-shell patterns
- newline-delimited JSON audit logging for executed Bash commands
- end-of-turn validation nudge for unverified change summaries
- pytest coverage for the main hook paths
- GitHub Actions CI workflow for tests and linting

### Fixed
- global install now writes target-aware absolute hook paths instead of assuming a Git repo context
- stop validator now returns valid JSON instead of invalid Python booleans
