# headersvalidator — Project Instructions

## Tech Stack
| Layer | Technology | Version |
|-------|-----------|---------|
| Language | Python | ≥ 3.11 |
| CLI framework | Typer | ≥ 0.12 |
| Terminal output | Rich | ≥ 13.7 |
| HTTP client | requests | ≥ 2.31 |
| Testing | pytest + pytest-cov | ≥ 8 / ≥ 5 |

## Build & Run
```bash
pip install -e .                        # install in editable mode
headersvalidator check https://example.com
headersvalidator info rules
python -m pytest                        # run tests with coverage
python -m pytest --tb=short -q          # quick run
```

## Project Structure
```
headersvalidator/
  cli.py          → Typer entry point; calls assessor + reporter
  assessor.py     → Public API: assess(url) → HeadersReport (only I/O here)
  checker.py      → Pure validation logic — HeadersChecker.check_all()
  constants.py    → HEADER_RULES table + per-header check functions
  models.py       → Status enum, HeaderResult, HeadersReport dataclasses
  reporter.py     → Rich terminal renderers (no I/O of its own)
  http_utils.py   → fetch_headers(), normalise_url(), extract_headers()
tests/
  conftest.py     → make_response() factory + SECURE/MINIMAL/EMPTY fixtures
  test_*.py       → pytest, AAA pattern, class-per-feature grouping
```

## Architecture
Request lifecycle:
1. CLI (`cli.py`) calls `assess(url)` from `assessor.py`
2. `assessor.py` calls `fetch_headers()` (HEAD with GET fallback on 405)
3. `extract_headers()` normalises headers to `{lowercase: value}`
4. `HeadersChecker.check_all()` applies every rule in `HEADER_RULES`
5. `HeadersReport` is returned; `reporter.py` renders it with Rich

**Single I/O boundary**: all network calls go through `http_utils.fetch_headers`.
Mock only this function in tests.

## Adding a New Header Rule
1. Add a `_check_fn(value) → tuple[Status, str]` function in `constants.py`
2. Append an entry to `HEADER_RULES` (name, iana_status, source, required, check, recommended, description)
3. Write tests in `tests/test_checker.py` and `tests/test_constants.py`

## Testing Conventions
- Mock boundary: `headersvalidator.http_utils.fetch_headers` via `monkeypatch`
- Use `conftest.make_response()` to build fake responses
- Fixtures: `secure_response`, `minimal_response`, `empty_response`, `mock_fetch`
- Test class naming: `TestCheckAll`, `TestAssess`, etc. (class-per-feature)
- Coverage configured in `pyproject.toml`; target ≥ 80%

## Scoring
PASS = 2 pts, WARN = 1 pt, FAIL/DEPRECATED = 0 pts (INFO not graded).
Score = `round(earned / (graded_count * 2) * 100)`.

## Exit Codes
- 0 — all required headers pass
- 1 — one or more FAIL (or WARN with `--strict`)
- 2 — network / connection error

## Conventions
- `from __future__ import annotations` at the top of every module
- Snake_case for all files, functions, and variables
- Sphinx-style docstrings: `:param name:`, `:returns:`, `:rtype:` (no `:type:` — type annotations on signatures are sufficient)
- Conventional commits: `fix:`, `feat:`, `fix(scope):`, `refactor:`, `test:`, `docs:`
- Input validation lives in `cli.py` (URL normalisation delegated to `normalise_url()` in `http_utils.py`)
- `fetch_headers()` from `http_utils` is the single I/O abstraction; patch it in tests via `monkeypatch`
- No CI config currently present

## Before Every Commit

Run these checks and update these files as needed — do not skip any step:

```bash
# 1. Verify tests pass and coverage is still 100%
pytest
```

If the test count changed, update **both** occurrences in `README.md`:
- Badge line (near top): `![Tests](https://img.shields.io/badge/tests-NNN%20passing-brightgreen)`
- Running Tests section: "The test suite has **NNN tests**…" sentence

Also update the count in **this file** (`CLAUDE.md`) under "Current State".

```bash
# 2. Check for lint issues
ruff check headersvalidator/
```

Fix any F401 (unused import) or other errors before committing.

## Version Bumping

When committing a set of changes, bump the version using semver:
- **patch** (`0.1.x`) — bug fixes, RFC compliance fixes, lint/refactor, docs
- **minor** (`0.x.0`) — new checks, new CLI commands, new features
- **major** (`x.0.0`) — breaking API changes

Two files must always be updated together:
- `pyproject.toml` → `version = "x.y.z"`
- `headersvalidator/__init__.py` → fallback `__version__ = "x.y.z"` (the `except` branch)
