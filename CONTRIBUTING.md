# Contributing

Thanks for wanting to improve the leash.

## Development setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
```

## Run checks

```bash
pytest
ruff check .
```

## Design principles

- be honest about Codex hook limitations
- prefer deterministic rules over clever magic
- fail closed for obviously risky behavior
- keep false positives understandable and easy to tune
- do not claim support for tool families Codex does not expose today

## Pull requests

Please keep PRs focused. A good PR usually includes:

- a clear summary of the behavior change
- tests for the new rule or regression
- README updates when the user-facing behavior changes
- a note on false-positive risk for any new blocking rule
