# Security Verdict & Grading Reference

> **Audience:** Security teams, CISOs, and anyone who wants to understand *why* a header
> is assigned a particular severity rather than just what the verdict is.

Every `headersvalidator check` run ends with a **Security Verdict** panel that lists
prioritised action items and assigns an **A+ – F letter grade** to the site's HTTP
security-header configuration.

---

## Contents

- [How the grade is calculated](#how-the-grade-is-calculated)
- [Severity levels explained](#severity-levels-explained)
- [Per-header reference](#per-header-reference)
- [Grade interpretation](#grade-interpretation)
- [Comparison with other tools](#comparison-with-other-tools)

---

## How the grade is calculated

The grading model is **penalty-based**: a perfect configuration starts at **0 penalty
points** (grade A+) and accumulates points as issues are found. Lower is better.

| Severity | Penalty | What it means |
|----------|---------|----------------|
| CRITICAL | 10 pts  | Active exploit is trivially possible when this control is absent or broken |
| HIGH     |  5 pts  | Significant weakening of the security posture; exploitation requires more effort |
| MEDIUM   |  2 pts  | Sub-optimal configuration; best-practice gap with no immediate exploit path |
| INFO     |  0 pts  | Observation only; zero penalty — shown for operator awareness |

Total penalty is mapped to a letter grade:

| Penalty points | Grade  | Interpretation |
|----------------|--------|----------------|
| 0              | **A+** | Perfect — no issues found |
| 1 – 10         | **A**  | Excellent — minor issues only |
| 11 – 20        | **B**  | Good — a few meaningful gaps |
| 21 – 30        | **C**  | Needs improvement — several important headers missing or misconfigured |
| 31 – 40        | **D**  | Poor — significant security exposure |
| > 40           | **F**  | Critical — immediate remediation required |

---

## Severity levels explained

### CRITICAL

A **CRITICAL** action means that the absence or misconfiguration of a header creates
a well-known, browser-exploitable attack vector **without requiring any additional
conditions to be true**.

The four headers that trigger CRITICAL when absent are the minimum baseline that every
public web server must deploy:

| Header | Attack prevented |
|--------|-----------------|
| `Strict-Transport-Security` | SSL stripping / protocol-downgrade (man-in-the-middle) |
| `Content-Security-Policy` | Cross-site scripting (XSS) — the single most exploited browser attack |
| `X-Frame-Options` | Clickjacking — user tricked into clicking invisible overlaid frames |
| `X-Content-Type-Options` | MIME-type confusion — browser executes an image or CSS file as a script |

These headers map to OWASP A05 (Security Misconfiguration) and A03 (Injection). They
are commonly tested by penetration testers, automated scanners (Qualys SSL Labs, Mozilla
Observatory), and bug-bounty hunters as first-pass checks. Any one of them absent is
a straightforward finding in a security assessment.

### HIGH

A **HIGH** action means the missing or misconfigured control weakens the security
posture materially, but exploitation typically requires an attacker to already have a
foothold (e.g. a network position, a compromised third party, or user interaction).

| Header | Why HIGH (not CRITICAL) |
|--------|------------------------|
| `Referrer-Policy` (absent) | Leaks URL paths and query strings to third parties on every navigation; enables information disclosure but does not directly enable code execution or session hijacking in isolation |
| `Permissions-Policy` (absent) | Leaves browser features (camera, microphone, geolocation) unrestricted for all embedded origins; a real risk but only exploitable if an attacker can inject content |
| Any required header present with a bad value | Header is present so the control partially exists; misconfiguration weakens rather than eliminates protection |

HIGH findings should be remediated in the same sprint as CRITICAL findings for
customer-facing applications handling sensitive data.

### MEDIUM

A **MEDIUM** action identifies a best-practice gap or sub-optimal configuration.
There is no direct exploit path, but the gap is worth closing:

- A required header is configured with a weak value (e.g. HSTS `max-age` below one year).
- An optional header is present with a bad value (e.g. `Cross-Origin-Opener-Policy: unsafe-none`).
- A deprecated header is being sent (e.g. `Expect-CT`) — removing it reduces the attack surface.

MEDIUM findings are reasonable remediation targets during normal hardening sprints.

### INFO

An **INFO** action carries **zero penalty** and does not affect the letter grade.
It surfaces observations about optional headers that are worth knowing:

- `Server` header discloses software name or version — useful to investigate, low urgency.
- `X-XSS-Protection` set to a non-zero value — legacy filter that can itself introduce
  vulnerabilities; worth updating to `0` on the next deployment cycle.

INFO items appear in the verdict panel for completeness so operators do not need to
cross-reference the results table separately.

---

## Per-header reference

The table below documents every header checked by headersvalidator, the attack it
prevents, and the severity assigned for each failure mode.

| Header | Required | Attack / Risk | Absent → | Misconfigured → | Notes |
|--------|----------|---------------|----------|-----------------|-------|
| **Strict-Transport-Security** | ✔ Tier 1 | SSL stripping, MITM downgrade | CRITICAL | MEDIUM (weak max-age / missing includeSubDomains) | RFC 6797 §6.1 |
| **Content-Security-Policy** | ✔ Tier 1 | XSS, data injection | CRITICAL | MEDIUM (unsafe-inline / unsafe-eval present) | W3C CSP Level 3 |
| **X-Frame-Options** | ✔ Tier 1 | Clickjacking | CRITICAL | MEDIUM (ALLOW-FROM deprecated) / FAIL (unknown value) | RFC 7034 |
| **X-Content-Type-Options** | ✔ Tier 1 | MIME-confusion attacks | CRITICAL | FAIL (any value other than `nosniff`) | RFC 9110 §8.3 |
| **Referrer-Policy** | ✔ Tier 2 | Information disclosure via Referer header | HIGH | MEDIUM (unsafe-url) | W3C Referrer Policy |
| **Permissions-Policy** | ✔ Tier 2 | Unrestricted camera / microphone / geolocation | HIGH | MEDIUM (sensitive features not addressed) | W3C Permissions Policy |
| **Cache-Control** | — Optional | Sensitive data cached on shared proxies | INFO | MEDIUM | RFC 9111 §5.2 |
| **Cross-Origin-Opener-Policy** | — Optional | Spectre / XS-Leaks cross-window attacks | INFO | MEDIUM / INFO | HTML Living Standard |
| **Cross-Origin-Embedder-Policy** | — Optional | Cross-origin isolation bypass | INFO | MEDIUM / INFO | HTML Living Standard |
| **Cross-Origin-Resource-Policy** | — Optional | Spectre-class resource inclusion | INFO | INFO (cross-origin) | Fetch Living Standard |
| **X-Permitted-Cross-Domain-Policies** | — Optional | Flash/PDF cross-domain data reads | INFO | INFO | OWASP |
| **Server** | — Optional | Software fingerprinting / version disclosure | — (not graded absent) | INFO (name/version revealed) | RFC 9110 §10.2.4 |
| **X-XSS-Protection** | — Optional | Legacy browser XSS-filter side effects | — (not graded absent) | INFO (non-zero value) | OWASP 2023 |
| **Expect-CT** | — Optional | Certificate Transparency opt-in (now native) | — (not graded absent) | MEDIUM (`DEPRECATED` verdict) | RFC 9163 (obsoleted) |

### Why CSP is CRITICAL but Permissions-Policy is only HIGH

`Content-Security-Policy` is the primary browser control against **cross-site scripting
(XSS)** — one of the most prevalent and impactful web vulnerabilities (OWASP Top 10 A03).
A site with no CSP is a site where an injected `<script>` tag runs with full origin
privileges: stealing session cookies, exfiltrating form data, redirecting the user,
or silently mining credentials. The attack is typically one injection payload away from
full account compromise. This is why absence earns CRITICAL.

`Permissions-Policy` controls **browser feature access** (camera, microphone,
geolocation, payment). Without it, an attacker who has already managed to inject content
(e.g. via XSS, a compromised third-party script, or a malicious ad) can request device
permissions from inside the page context. The attack requires a **prior foothold** —
you cannot exploit a missing Permissions-Policy header from outside the page. That
two-step dependency is why absence earns HIGH rather than CRITICAL.

The same logic distinguishes Tier-1 from Tier-2 across the board:

- **Tier-1 (CRITICAL absent):** Absent → browser-level exploit path with no prior
  conditions. SSL stripping (STS), XSS (CSP), clickjacking (XFO), MIME execution (XCTO).
- **Tier-2 (HIGH absent):** Absent → information leak or privilege escalation, but
  only once another condition is true (Referer leaks need the user to navigate;
  Permissions-Policy abuse needs injected content).

---

## Grade interpretation

| Grade | What it means | Recommended action |
|-------|--------------|-------------------|
| **A+** | No issues — all evaluated headers pass | Monitor; re-check after infrastructure changes |
| **A**  | Excellent posture; minor sub-optimal values | Schedule MEDIUM fixes in next hardening sprint |
| **B**  | Good baseline; one or two meaningful gaps | Address HIGH findings within the quarter |
| **C**  | Needs improvement; several required headers missing or misconfigured | Treat as a sprint priority; raise to security team |
| **D**  | Poor — multiple critical controls absent | Escalate; block deployment to production if applicable |
| **F**  | Critical exposure — immediate risk | Emergency remediation required; consider temporary mitigations |

---

## Comparison with other tools

headersvalidator uses a stricter CSP grader than many commercial scanners: if
`unsafe-inline` or `unsafe-eval` are present the verdict is WARN (MEDIUM penalty),
not PASS. Sites that score A on Mozilla Observatory or Qualys may therefore grade one
band lower here. This is intentional — a CSP that permits `unsafe-inline` offers only
marginal XSS protection and should be flagged in any security assessment.

---

*References: RFC 6797, RFC 7034, RFC 9110, RFC 9111, RFC 9163,
W3C CSP Level 3, W3C Referrer Policy, W3C Permissions Policy,
HTML Living Standard, Fetch Living Standard,
[OWASP HTTP Headers Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html),
[IANA HTTP Field Name Registry](https://www.iana.org/assignments/http-fields/).*
