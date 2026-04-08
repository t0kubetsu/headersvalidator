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
