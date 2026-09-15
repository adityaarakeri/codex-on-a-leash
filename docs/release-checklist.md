# Release checklist

## Before tagging

- [ ] run `pytest`
- [ ] run `ruff check .`
- [ ] run `python3 scripts/check_release_metadata.py`
- [ ] confirm active hook configuration uses `[features].hooks` and has no unresolved hook template
- [ ] regenerate package metadata from `README.md` and confirm its version matches `pyproject.toml`
- [ ] confirm `README.md` examples still match the installer output
- [ ] review `CHANGELOG.md`
- [ ] review `RELEASE.md`
- [ ] verify `install.sh --dry-run`
- [ ] verify `install.sh --uninstall --dry-run`
- [ ] remove accidental local artifacts
- [ ] create tag `vX.Y.Z`
- [ ] publish GitHub release notes from `RELEASE.md`
