"""
Validation rules for HTTP response headers.

Every entry is derived from three authoritative sources:
  - RFC 9110  (HTTP Semantics)            — field semantics and requirements
  - RFC 9111  (HTTP Caching)              — Cache-Control directives
  - OWASP HTTP Headers Cheat Sheet        — security pass/fail criteria
  - IANA HTTP Field Name Registry         — field registration status

Rule format
-----------
Each entry in HEADER_RULES is a dict with keys:

  name          str   Canonical field name (matches IANA registry spelling)
  iana_status   str   "permanent" | "provisional" | "deprecated" | "obsoleted"
  source        str   Primary reference citation
  required      bool  Must be present (FAIL if absent) — driven by OWASP
  check         callable(value: str) -> tuple[Status, str]
                      Returns (status, reason).  Called only when header is present.
  recommended   str   Recommended value or directive string shown in the report
  description   str   One-line purpose description
"""

from __future__ import annotations

import re

from headersvalidator.models import Status

# ---------------------------------------------------------------------------
# Helper predicates
# ---------------------------------------------------------------------------


def _hsts_check(value: str) -> tuple[Status, str]:
    """
    Validate Strict-Transport-Security against OWASP requirements.

    OWASP: max-age ≥ 31536000 (1 year), includeSubDomains present.
    RFC 6797 §6.1 defines the directive grammar.

    :param value: Raw header value string.
    :returns: A ``(Status, reason)`` tuple describing the verdict.
    :rtype: tuple[Status, str]
    """
    v = value.lower()
    # Extract max-age
    m = re.search(r"max-age\s*=\s*(\d+)", v)
    if not m:
        return Status.FAIL, "max-age directive is missing"
    age = int(m.group(1))
    if age < 31_536_000:
        return Status.WARN, f"max-age={age} is below the recommended 31536000 (1 year)"
    if "includesubdomains" not in v:
        return (
            Status.WARN,
            "includeSubDomains directive is absent; sub-domains are not protected",
        )
    return Status.PASS, "max-age ≥ 1 year and includeSubDomains present"


def _csp_check(value: str) -> tuple[Status, str]:
    """
    Validate Content-Security-Policy against OWASP requirements.

    OWASP: must not contain 'unsafe-inline' for scripts; should define default-src.
    RFC 9110 §12 + W3C CSP Level 3.

    :param value: Raw header value string.
    :returns: A ``(Status, reason)`` tuple describing the verdict.
    :rtype: tuple[Status, str]
    """
    v = value.lower()
    issues = []
    if "default-src" not in v and "script-src" not in v:
        issues.append("no default-src or script-src directive")
    if "'unsafe-inline'" in v:
        issues.append("'unsafe-inline' weakens XSS protection")
    if "'unsafe-eval'" in v:
        issues.append("'unsafe-eval' allows dynamic code execution")
    if issues:
        return Status.WARN, "; ".join(issues)
    return Status.PASS, "CSP is present with no obviously unsafe directives"


def _x_frame_check(value: str) -> tuple[Status, str]:
    """
    Validate X-Frame-Options against OWASP requirements.

    OWASP: DENY or SAMEORIGIN are acceptable; ALLOW-FROM is deprecated.

    :param value: Raw header value string.
    :returns: A ``(Status, reason)`` tuple describing the verdict.
    :rtype: tuple[Status, str]
    """
    v = value.strip().upper()
    if v in ("DENY", "SAMEORIGIN"):
        return Status.PASS, f"X-Frame-Options: {v} prevents clickjacking"
    if v.startswith("ALLOW-FROM"):
        return (
            Status.WARN,
            "ALLOW-FROM is not supported by modern browsers; use CSP frame-ancestors",
        )
    return Status.FAIL, f"Unrecognised X-Frame-Options value: {value!r}"


def _xcto_check(value: str) -> tuple[Status, str]:
    """
    Validate X-Content-Type-Options against OWASP requirements.

    OWASP: must be 'nosniff'. RFC 9110 §8.3.

    :param value: Raw header value string.
    :returns: A ``(Status, reason)`` tuple describing the verdict.
    :rtype: tuple[Status, str]
    """
    if value.strip().lower() == "nosniff":
        return Status.PASS, "MIME-type sniffing is disabled"
    return Status.FAIL, f"Expected 'nosniff', got {value!r}"


def _referrer_check(value: str) -> tuple[Status, str]:
    """
    Validate Referrer-Policy against OWASP requirements.

    OWASP: safe values are no-referrer, strict-origin, strict-origin-when-cross-origin.
    Unsafe values are unsafe-url and no-referrer-when-downgrade.

    :param value: Raw header value string.
    :returns: A ``(Status, reason)`` tuple describing the verdict.
    :rtype: tuple[Status, str]
    """
    safe = {
        "no-referrer",
        "no-referrer-when-downgrade",  # borderline — accepted, not ideal
        "origin",
        "origin-when-cross-origin",
        "same-origin",
        "strict-origin",
        "strict-origin-when-cross-origin",
    }
    v = value.strip().lower()
    if v == "unsafe-url":
        return (
            Status.FAIL,
            "unsafe-url sends full URL including query strings cross-origin",
        )
    if v == "no-referrer-when-downgrade":
        return (
            Status.WARN,
            "no-referrer-when-downgrade leaks origin+path+query on same-protocol requests",
        )
    if v in safe:
        return (
            Status.PASS,
            f"Referrer-Policy '{v}' limits referrer exposure appropriately",
        )
    return Status.WARN, f"Unrecognised Referrer-Policy value: {value!r}"


def _cache_control_check(value: str) -> tuple[Status, str]:
    """
    Validate Cache-Control against RFC 9111 and OWASP requirements.

    RFC 9111 §5.2: validate Cache-Control directives for sensitive responses.
    OWASP: authenticated pages should use no-store.

    :param value: Raw header value string.
    :returns: A ``(Status, reason)`` tuple describing the verdict.
    :rtype: tuple[Status, str]
    """
    v = value.lower()
    issues = []
    if "public" in v and "no-store" not in v:
        issues.append("'public' may cache authenticated responses on shared proxies")
    if "max-age=0" in v or "no-cache" in v or "no-store" in v:
        # Protective directives present — good
        pass
    elif "s-maxage" not in v and "max-age" not in v and "no-store" not in v:
        issues.append(
            "no explicit caching lifetime; RFC 9111 recommends explicit directives"
        )
    if issues:
        return Status.WARN, "; ".join(issues)
    return Status.PASS, "Cache-Control directives are explicitly stated"


def _permissions_check(value: str) -> tuple[Status, str]:
    """
    Validate Permissions-Policy against OWASP requirements.

    OWASP: should restrict sensitive features (geolocation, camera, microphone).

    :param value: Raw header value string.
    :returns: A ``(Status, reason)`` tuple describing the verdict.
    :rtype: tuple[Status, str]
    """
    v = value.lower()
    sensitive = ["geolocation", "camera", "microphone"]
    unrestricted = [f for f in sensitive if f"={f}" not in v and f not in v]
    if unrestricted:
        # If the header is present at all it is already an improvement
        return Status.WARN, (
            f"Permissions-Policy does not explicitly restrict: {', '.join(unrestricted)}"
        )
    return Status.PASS, "Sensitive features are addressed in Permissions-Policy"


def _coop_check(value: str) -> tuple[Status, str]:
    """
    Validate Cross-Origin-Opener-Policy against OWASP requirements.

    OWASP: same-origin provides the strongest isolation against XS-Leaks.

    :param value: Raw header value string.
    :returns: A ``(Status, reason)`` tuple describing the verdict.
    :rtype: tuple[Status, str]
    """
    v = value.strip().lower()
    if v == "same-origin":
        return (
            Status.PASS,
            "Browsing context is isolated to same-origin (Spectre mitigation)",
        )
    if v in ("same-origin-allow-popups",):
        return (
            Status.WARN,
            "same-origin-allow-popups provides partial isolation; prefer same-origin",
        )
    if v == "unsafe-none":
        return Status.FAIL, "unsafe-none disables cross-origin isolation"
    return Status.WARN, f"Unrecognised COOP value: {value!r}"


def _coep_check(value: str) -> tuple[Status, str]:
    """
    Validate Cross-Origin-Embedder-Policy against OWASP requirements.

    OWASP: require-corp or credentialless enable cross-origin isolation.

    :param value: Raw header value string.
    :returns: A ``(Status, reason)`` tuple describing the verdict.
    :rtype: tuple[Status, str]
    """
    v = value.strip().lower()
    if v in ("require-corp", "credentialless"):
        return Status.PASS, f"COEP '{v}' enables cross-origin isolation"
    if v == "unsafe-none":
        return Status.FAIL, "unsafe-none disables cross-origin embedding protection"
    return Status.WARN, f"Unrecognised COEP value: {value!r}"


def _corp_check(value: str) -> tuple[Status, str]:
    """
    Validate Cross-Origin-Resource-Policy against OWASP requirements.

    OWASP: same-origin or same-site prevent Spectre-class resource inclusion attacks.

    :param value: Raw header value string.
    :returns: A ``(Status, reason)`` tuple describing the verdict.
    :rtype: tuple[Status, str]
    """
    v = value.strip().lower()
    if v == "same-origin":
        return Status.PASS, "Resources are restricted to same-origin only"
    if v == "same-site":
        return Status.PASS, "Resources are restricted to same-site"
    if v == "cross-origin":
        return Status.WARN, "cross-origin permits any origin to include this resource"
    return Status.WARN, f"Unrecognised CORP value: {value!r}"


def _server_check(value: str) -> tuple[Status, str]:
    """
    Validate Server header against OWASP information-disclosure guidance.

    OWASP: Server header should not reveal product version strings.
    RFC 9110 §10.2.4 notes implementors MAY omit or obscure it.

    :param value: Raw header value string.
    :returns: A ``(Status, reason)`` tuple describing the verdict.
    :rtype: tuple[Status, str]
    """
    # Heuristic: version numbers, software names are a fingerprinting risk
    giveaways = re.compile(
        r"(apache|nginx|iis|lighttpd|caddy|litespeed|openresty|gunicorn|uvicorn|tornado)"
        r"|\d+\.\d+",
        re.IGNORECASE,
    )
    if giveaways.search(value):
        return Status.WARN, (
            "Server header reveals software identity/version; "
            "OWASP recommends removing or setting a non-informative value"
        )
    return Status.INFO, "Server header present with non-informative value"


def _xpcdp_check(value: str) -> tuple[Status, str]:
    """
    Validate X-Permitted-Cross-Domain-Policies against OWASP requirements.

    OWASP: none or master-only limits Adobe Flash/PDF cross-domain access.

    :param value: Raw header value string.
    :returns: A ``(Status, reason)`` tuple describing the verdict.
    :rtype: tuple[Status, str]
    """
    v = value.strip().lower()
    if v in ("none", "master-only"):
        return (
            Status.PASS,
            f"X-Permitted-Cross-Domain-Policies: {v} restricts Flash/PDF access",
        )
    return Status.WARN, f"Value '{v}' may allow broad cross-domain access"


def _x_xss_check(value: str) -> tuple[Status, str]:
    """
    Validate X-XSS-Protection against OWASP 2023 guidance.

    OWASP 2023: X-XSS-Protection is deprecated.
    Recommended value is '0' (disabled) to avoid browser-level XSS filter bugs.

    :param value: Raw header value string.
    :returns: A ``(Status, reason)`` tuple describing the verdict.
    :rtype: tuple[Status, str]
    """
    v = value.strip()
    if v == "0":
        return (
            Status.PASS,
            "X-XSS-Protection: 0 is the current recommended value (disables legacy filter)",
        )
    return Status.WARN, (
        f"Value '{v}' enables a deprecated browser filter that can itself introduce "
        "security issues; set to 0 or remove the header"
    )


def _expect_ct_check(value: str) -> tuple[Status, str]:
    """
    Flag Expect-CT as deprecated per OWASP 2023 guidance.

    OWASP 2023: Expect-CT is deprecated; browsers enforce CT natively.

    :param value: Raw header value string (not inspected; header is always deprecated).
    :returns: A ``(Status.DEPRECATED, reason)`` tuple.
    :rtype: tuple[Status, str]
    """
    return Status.DEPRECATED, (
        "Expect-CT is deprecated (as of 2023); modern browsers enforce Certificate "
        "Transparency natively. Remove this header."
    )


# ---------------------------------------------------------------------------
# Master rules table
# ---------------------------------------------------------------------------
# Each dict is consumed by checker.py to drive per-header validation.

HEADER_RULES: list[dict] = [
    # ------------------------------------------------------------------
    # 1. Strict-Transport-Security  (RFC 6797 + OWASP)
    # ------------------------------------------------------------------
    {
        "name": "Strict-Transport-Security",
        "iana_status": "permanent",
        "source": "RFC 6797 §6.1 + OWASP",
        "required": True,
        "absent_severity": "CRITICAL",
        "check": _hsts_check,
        "recommended": "max-age=63072000; includeSubDomains; preload",
        "description": "Forces HTTPS-only access and prevents protocol-downgrade attacks.",
    },
    # ------------------------------------------------------------------
    # 2. Content-Security-Policy  (W3C CSP3 + OWASP)
    # ------------------------------------------------------------------
    {
        "name": "Content-Security-Policy",
        "iana_status": "permanent",
        "source": "W3C CSP Level 3 + OWASP",
        "required": True,
        "absent_severity": "CRITICAL",
        "check": _csp_check,
        "recommended": "default-src 'self'; object-src 'none'; base-uri 'self'; upgrade-insecure-requests",
        "description": "Controls allowed resource origins; mitigates XSS and data-injection.",
    },
    # ------------------------------------------------------------------
    # 3. X-Frame-Options  (RFC 7034 + OWASP)
    # ------------------------------------------------------------------
    {
        "name": "X-Frame-Options",
        "iana_status": "permanent",
        "source": "RFC 7034 + OWASP",
        "required": True,
        "absent_severity": "CRITICAL",
        "check": _x_frame_check,
        "recommended": "DENY",
        "description": "Prevents clickjacking by controlling framing. Superseded by CSP frame-ancestors.",
    },
    # ------------------------------------------------------------------
    # 4. X-Content-Type-Options  (OWASP + RFC 9110 §8.3)
    # ------------------------------------------------------------------
    {
        "name": "X-Content-Type-Options",
        "iana_status": "permanent",
        "source": "RFC 9110 §8.3 + OWASP",
        "required": True,
        "absent_severity": "CRITICAL",
        "check": _xcto_check,
        "recommended": "nosniff",
        "description": "Prevents MIME-type sniffing that can turn safe content into executable code.",
    },
    # ------------------------------------------------------------------
    # 5. Referrer-Policy  (W3C Referrer Policy + OWASP)
    # ------------------------------------------------------------------
    {
        "name": "Referrer-Policy",
        "iana_status": "permanent",
        "source": "W3C Referrer Policy + OWASP",
        "required": True,
        "absent_severity": "HIGH",
        "check": _referrer_check,
        "recommended": "strict-origin-when-cross-origin",
        "description": "Controls how much referrer information is sent with requests.",
    },
    # ------------------------------------------------------------------
    # 6. Cache-Control  (RFC 9111 §5.2 + OWASP)
    # ------------------------------------------------------------------
    {
        "name": "Cache-Control",
        "iana_status": "permanent",
        "source": "RFC 9111 §5.2 + OWASP",
        "required": False,
        "check": _cache_control_check,
        "recommended": "no-store, max-age=0",
        "description": "Declares cacheability; RFC 9111 recommends explicit directives for correctness.",
    },
    # ------------------------------------------------------------------
    # 7. Permissions-Policy  (W3C Permissions Policy + OWASP)
    # ------------------------------------------------------------------
    {
        "name": "Permissions-Policy",
        "iana_status": "permanent",
        "source": "W3C Permissions Policy + OWASP",
        "required": True,
        "absent_severity": "HIGH",
        "check": _permissions_check,
        "recommended": "geolocation=(), camera=(), microphone=(), payment=()",
        "description": "Limits access to browser features (camera, geolocation, etc.).",
    },
    # ------------------------------------------------------------------
    # 8. Cross-Origin-Opener-Policy  (HTML spec + OWASP)
    # ------------------------------------------------------------------
    {
        "name": "Cross-Origin-Opener-Policy",
        "iana_status": "permanent",
        "source": "HTML Living Standard + OWASP",
        "required": False,
        "check": _coop_check,
        "recommended": "same-origin",
        "description": "Isolates the browsing context to mitigate Spectre / XS-Leaks attacks.",
    },
    # ------------------------------------------------------------------
    # 9. Cross-Origin-Embedder-Policy  (HTML spec + OWASP)
    # ------------------------------------------------------------------
    {
        "name": "Cross-Origin-Embedder-Policy",
        "iana_status": "permanent",
        "source": "HTML Living Standard + OWASP",
        "required": False,
        "check": _coep_check,
        "recommended": "require-corp",
        "description": "Requires explicit cross-origin resource permissions; enables cross-origin isolation.",
    },
    # ------------------------------------------------------------------
    # 10. Cross-Origin-Resource-Policy  (Fetch spec + OWASP)
    # ------------------------------------------------------------------
    {
        "name": "Cross-Origin-Resource-Policy",
        "iana_status": "permanent",
        "source": "Fetch Living Standard + OWASP",
        "required": False,
        "check": _corp_check,
        "recommended": "same-origin",
        "description": "Controls which origins may include this resource; mitigates Spectre attacks.",
    },
    # ------------------------------------------------------------------
    # 11. X-Permitted-Cross-Domain-Policies  (OWASP)
    # ------------------------------------------------------------------
    {
        "name": "X-Permitted-Cross-Domain-Policies",
        "iana_status": "provisional",
        "source": "OWASP",
        "required": False,
        "check": _xpcdp_check,
        "recommended": "none",
        "description": "Restricts Adobe Flash/PDF cross-domain requests.",
    },
    # ------------------------------------------------------------------
    # 12. Server  (RFC 9110 §10.2.4 + OWASP)
    # ------------------------------------------------------------------
    {
        "name": "Server",
        "iana_status": "permanent",
        "source": "RFC 9110 §10.2.4 + OWASP",
        "required": False,
        "check": _server_check,
        "recommended": "<empty or non-informative>",
        "description": "Should not reveal software name or version (information disclosure).",
    },
    # ------------------------------------------------------------------
    # 13. X-XSS-Protection  (OWASP — deprecated, check for 0)
    # ------------------------------------------------------------------
    {
        "name": "X-XSS-Protection",
        "iana_status": "provisional",
        "source": "OWASP (deprecated)",
        "required": False,
        "check": _x_xss_check,
        "recommended": "0",
        "description": "Legacy XSS filter. OWASP recommends setting to 0 or removing entirely.",
    },
    # ------------------------------------------------------------------
    # 14. Expect-CT  (OWASP — deprecated, flag presence)
    # ------------------------------------------------------------------
    {
        "name": "Expect-CT",
        "iana_status": "obsoleted",
        "source": "RFC 9163 (obsoleted) + OWASP",
        "required": False,
        "check": _expect_ct_check,
        "recommended": "<remove this header>",
        "description": "Certificate Transparency opt-in. Deprecated — CT is now enforced natively.",
    },
]

# Lookup by normalised lower-case name for O(1) access in checker
RULES_BY_NAME: dict[str, dict] = {r["name"].lower(): r for r in HEADER_RULES}

# HTTP request timeout in seconds (mirrors chainvalidator's DNS_TIMEOUT pattern)
HTTP_TIMEOUT: float = 10.0

# Default User-Agent used for requests
USER_AGENT: str = (
    "headersvalidator/0.1.0 (+https://github.com/t0kubetsu/headersvalidator)"
)
