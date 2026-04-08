# headersvalidator

> Validate the HTTP response headers of any URL — from the command line or as a Python library.

**headersvalidator** fetches a URL and checks every security-relevant response header against
RFC 9110, RFC 9111, the OWASP HTTP Headers Cheat Sheet, and the IANA HTTP Field Name Registry,
producing a colour-coded report and a 0–100 security score.

```
$ headersvalidator check example.com
```

![Python](https://img.shields.io/badge/python-%3E%3D3.11-blue)
![Tests](https://img.shields.io/badge/tests-315%20passing-brightgreen)
![Coverage](https://img.shields.io/badge/coverage-100%25-brightgreen)
![License](https://img.shields.io/badge/license-GPLv3-lightgrey)

---

## Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [CLI Usage](#cli-usage)
- [Python API](#python-api)
- [Scoring](#scoring)
- [Security Verdict & Grading](#security-verdict--grading)
- [Project Structure](#project-structure)
- [Running Tests](#running-tests)
- [Contributing](#contributing)

---

## Features

| Header                                | Required | What is verified                                                                                 |
| ------------------------------------- | -------- | ------------------------------------------------------------------------------------------------ |
| **Strict-Transport-Security**         | ✔        | `max-age` ≥ 31 536 000 (1 year); `includeSubDomains` present; `preload` noted                    |
| **Content-Security-Policy**           | ✔        | `default-src` or `script-src` must be present; `'unsafe-inline'` and `'unsafe-eval'` are flagged |
| **X-Frame-Options**                   | ✔        | `DENY` or `SAMEORIGIN` pass; `ALLOW-FROM` warned (obsolete); any other value fails               |
| **X-Content-Type-Options**            | ✔        | Must be exactly `nosniff` (RFC 9110 §8.3)                                                        |
| **Referrer-Policy**                   | ✔        | `unsafe-url` fails; `no-referrer-when-downgrade` warns; all W3C safe values pass                 |
| **Cache-Control**                     | ✔        | RFC 9111: explicit lifetime directives required; `public` without `no-store` warned              |
| **Permissions-Policy**                | —        | Sensitive features (`geolocation`, `camera`, `microphone`) must be explicitly addressed          |
| **Cross-Origin-Opener-Policy**        | —        | `same-origin` passes; `same-origin-allow-popups` warns; `unsafe-none` fails                      |
| **Cross-Origin-Embedder-Policy**      | —        | `require-corp` / `credentialless` pass; `unsafe-none` fails                                      |
| **Cross-Origin-Resource-Policy**      | —        | `same-origin` / `same-site` pass; `cross-origin` warns                                           |
| **X-Permitted-Cross-Domain-Policies** | —        | `none` / `master-only` pass; any broader value warns                                             |
| **Server**                            | —        | Software name or version strings warned (information disclosure)                                 |
| **X-XSS-Protection**                  | —        | `0` passes (OWASP 2023 recommendation); any other value warns                                    |
| **Expect-CT**                         | —        | Always flagged `DEPRECATED` — CT is enforced natively by browsers                                |

Five verdict levels: `PASS`, `WARN`, `FAIL`, `INFO` (optional absent headers), `DEPRECATED` (obsolete headers).

---

## Requirements

- Python ≥ 3.11
- [`requests`](https://docs.python-requests.org/) ≥ 2.31
- [`rich`](https://github.com/Textualize/rich) ≥ 13.7
- [`typer`](https://typer.tiangolo.com/) ≥ 0.12

---

## Installation

**From source (recommended):**

```bash
git clone https://github.com/t0kubetsu/headersvalidator.git
cd headersvalidator
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"   # installs the CLI + all dev/test dependencies
```

The `headersvalidator` command is then available in your shell.

---

## CLI Usage

### Full report

```bash
# Validate a URL (https:// assumed if no scheme given)
headersvalidator check example.com
headersvalidator check https://example.com

# Adjust request timeout (seconds, default 10)
headersvalidator check example.com --timeout 15

# Skip TLS certificate verification (internal hosts)
headersvalidator check https://intranet.local --no-tls-verify

# Output as JSON (for CI/CD pipelines)
headersvalidator check example.com --json

# Exit code 1 on WARN as well as FAIL (strict mode)
headersvalidator check example.com --strict
```

### Reference tables

```bash
headersvalidator info rules      # All rules with recommended values
headersvalidator info sources    # Reference source URLs
headersvalidator info iana       # IANA registration status per header
```

### Version

```bash
headersvalidator --version
```

---

## Python API

### Full assessment

```python
from headersvalidator.assessor import assess
from headersvalidator.reporter import print_full_report

report = assess(
    "example.com",
    timeout=10.0,      # optional: request timeout in seconds
    verify_tls=True,   # optional: set False to skip TLS verification
)

print_full_report(report)
```

### Working with results

```python
from headersvalidator.assessor import assess
from headersvalidator.models import Status

report = assess("example.com")

print(report.status)        # Status.PASS | WARN | FAIL
print(report.is_pass)       # True / False
print(report.score)         # 0–100
print(report.url)           # "https://example.com"
print(report.final_url)     # effective URL after redirects
print(report.status_code)   # HTTP status code

# Iterate over all results
for result in report.results:
    print(result.name, result.status.value, result.reason)
    print("  recommended:", result.recommended)
    print("  IANA status:", result.iana_status)
    print("  source:     ", result.source)

# Look up a specific header by name (case-insensitive)
hsts = report.by_name("Strict-Transport-Security")
if hsts:
    print(hsts.value, hsts.status)

# Filtered slices
print(report.passed)      # list[HeaderResult] — status PASS
print(report.warned)      # list[HeaderResult] — status WARN
print(report.failed)      # list[HeaderResult] — status FAIL
print(report.deprecated)  # list[HeaderResult] — status DEPRECATED
```

`Status` values: `PASS`, `WARN`, `FAIL`, `INFO`, `DEPRECATED`.

---

## Security Verdict & Grading

Every `headersvalidator check` run ends with a **Security Verdict** panel listing
prioritised action items and an **A+ – F letter grade** based on a penalty-point model.

For a full explanation of severity levels, the per-header threat model, and why certain
headers (e.g. CSP) are rated CRITICAL while others (e.g. Permissions-Policy) are HIGH,
see **[docs/SECURITY_VERDICT.md](docs/SECURITY_VERDICT.md)**.

| Severity | Penalty | When assigned |
| -------- | ------- | ------------- |
| CRITICAL | 10 pts  | Tier-1 header absent (STS, CSP, XFO, XCTO) — direct exploit path |
| HIGH     |  5 pts  | Tier-2 header absent (Referrer-Policy, Permissions-Policy) or bad value on required header |
| MEDIUM   |  2 pts  | Sub-optimal value on required header; bad value on optional header; deprecated header present |
| INFO     |  0 pts  | Observation on optional header — shown in panel, zero penalty |

Grade thresholds: **0 → A+** · **1–10 → A** · **11–20 → B** · **21–30 → C** · **31–40 → D** · **> 40 → F**

---

## Scoring

Every `headersvalidator check` run ends with a **score panel** (0–100) and a
qualitative label based on the weighted verdict counts.

### How the score is calculated

| Verdict    | Points     |
| ---------- | ---------- |
| PASS       | 2 pts      |
| WARN       | 1 pt       |
| FAIL       | 0 pts      |
| DEPRECATED | 0 pts      |
| INFO       | not graded |

```
score = round(earned / (graded_count × 2) × 100)
```

### Score thresholds

| Score   | Label                 |
| ------- | --------------------- |
| ≥ 80    | **Good**              |
| 50 – 79 | **Needs improvement** |
| < 50    | **Poor**              |

---

## Exit Codes

| Code | Meaning                                                                |
| ---- | ---------------------------------------------------------------------- |
| `0`  | All required headers pass (or only optional headers are absent/warned) |
| `1`  | One or more required headers fail; or any WARN with `--strict`         |
| `2`  | Network / connection error (unreachable host, DNS failure, TLS error)  |

---

## Project Structure

```
headersvalidator/
├── headersvalidator/
│   ├── __init__.py         Package version, NullHandler
│   ├── assessor.py         assess() — public API entry point
│   ├── checker.py          HeadersChecker — core validation logic
│   ├── cli.py              Typer CLI: check, info sub-commands
│   ├── constants.py        HEADER_RULES, RULES_BY_NAME, HTTP_TIMEOUT
│   ├── http_utils.py       fetch_headers, normalise_url, extract_headers
│   ├── models.py           Status, HeaderResult, HeadersReport
│   └── reporter.py         print_full_report and section printers (Rich)
├── tests/
│   ├── conftest.py         Shared fixtures and factories
│   ├── test_assessor.py
│   ├── test_checker.py
│   ├── test_cli.py
│   ├── test_constants.py
│   ├── test_http_utils.py
│   ├── test_models.py
│   └── test_reporter.py
├── pyproject.toml
├── requirements.txt
├── requirements-dev.txt
└── README.md
```

---

## Running Tests

```bash
source .venv/bin/activate

# Run all tests with coverage
pytest

# Quick run (short tracebacks)
pytest --tb=short -q

# Run a single module
pytest tests/test_checker.py

# Run a single test class
pytest tests/test_checker.py::TestHSTS -v
```

The test suite has **309 tests** and maintains **100% statement coverage**.

All HTTP network I/O (`requests.head`, `requests.get`) is mocked at the
`fetch_headers` boundary — no test touches a real server or the internet.

---

## Contributing

1. Fork the repository and create a feature branch.
2. Follow the [project conventions](CLAUDE.md) — AAA test pattern, class-per-feature grouping.
3. Add tests for any new header rule or behaviour change.
4. Ensure `pytest` passes with 100% coverage before opening a pull request.

---

## License

GPLv3 — see [LICENSE](LICENSE) for details.
