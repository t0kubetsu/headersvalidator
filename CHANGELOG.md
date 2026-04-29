# Changelog

All notable changes to **headersvalidator** are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Version numbers follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

---

## [0.1.2] — 2026-04-08

### Added
- Report header now shows the final redirect destination URL when a redirect
  was followed during the header fetch.

---

## [0.1.1] — 2026-04-08

### Fixed
- HTTP redirect followed correctly when the `https://` port is closed and
  the server redirects to `http://`.

---

## [0.1.0] — 2026-04-08

### Added
- Initial release of **headersvalidator**.
- HTTP security-header validation against RFC 9110/9111, OWASP, and the IANA
  header registry.
- Scoring model: `PASS` / `WARN` / `FAIL` / `DEPRECATED` / `INFO` status per
  header; letter-grade verdict (A+…F) derived from weighted penalty points.
- Security Verdict panel with actionable recommendations surfaced in the
  terminal report.
- CLI: `headersvalidator check <url-or-domain>` with `--json`, `--output`,
  `--strict` flags.
- `headersvalidator info rules` — lists all evaluated header rules.
- Report export to `.txt`, `.svg`, `.html`.
- HEAD with GET fallback (on HTTP 405) for header fetching.

---

[Unreleased]: https://github.com/NC3-TestingPlatform/headersvalidator/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/NC3-TestingPlatform/headersvalidator/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/NC3-TestingPlatform/headersvalidator/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/NC3-TestingPlatform/headersvalidator/releases/tag/v0.1.0
