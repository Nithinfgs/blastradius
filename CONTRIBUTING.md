# Contributing

Thanks for helping. The most valuable contributions are:

1. **New feeds** in `src/blastradius/feeds/`. Link a primary source in `source`, use the `caveats` field to say what was and was not verified, and never include real malware samples, only names and hashes.
2. **Lockfile parser fixes** with a test in `tests/test_lockfiles.py`.
3. Bug reports with a minimal synthetic directory layout that reproduces the problem.

## Setup

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
```

## Before opening a pull request

```bash
.venv/bin/pytest -q
.venv/bin/ruff check . && .venv/bin/ruff format --check .
.venv/bin/mypy src
```

Guidelines:

- Keep runtime dependencies at zero.
- Never open credential files; only check that paths exist.
- Tests must use temp directories and benign fixtures. Do not commit anything that behaves like malware.
- Add a line to `CHANGELOG.md`.
