# Security Assessment Report: Missing Security Headers

**Project:** Missing Security Headers (CSP/HSTS/X-Frame-Options) Detection Tool
**Internship:** SafeX — Week 4
**Target:** OWASP Juice Shop (local instance, `http://localhost:3000`)
**Date:** 2026-09-20

---

## 1. Scope & Authorization

Testing was performed exclusively against a **locally-run OWASP Juice Shop instance** deployed via Docker on the tester's own machine (`http://localhost:3000`), bound to `localhost` only and not exposed externally. No external, third-party, or unauthorized systems were scanned. Juice Shop is an OWASP-maintained application explicitly built and distributed as an intentionally-vulnerable target for this kind of security testing.

## 2. Objective

Design and build a reusable, automated detection tool for three commonly-missing HTTP security headers — Content-Security-Policy (CSP), Strict-Transport-Security (HSTS), and X-Frame-Options — and use it to produce a professional findings report against an authorized lab target.

## 3. Methodology

The tool (`header_scanner.py`) sends a standard GET request to each URL in the provided list and inspects the response headers for:

- **Content-Security-Policy** — flagged as *missing* if absent; flagged as *weak* if present but containing `unsafe-inline`, `unsafe-eval`, or a wildcard (`*`) source.
- **Strict-Transport-Security** — only evaluated on HTTPS targets (not applicable over plain HTTP); flagged *missing* if absent, *weak* if `max-age` is under ~6 months.
- **X-Frame-Options** — flagged *missing* only if neither the header nor an equivalent CSP `frame-ancestors` directive is present.

**False-positive control:** any "missing" result triggers a second, independent confirmation request before being reported, ruling out one-off network blips.

**Validation before use:** prior to scanning the live target, the tool was tested against two local mock servers during development — one serving no security headers (to confirm true-positive detection) and one serving correctly-configured CSP and X-Frame-Options headers (to confirm zero false positives). Both behaved as expected, giving confidence in the tool's accuracy before pointing it at Juice Shop.

## 4. Summary of Findings

| Metric | Value |
|---|---|
| URLs scanned | 3 |
| Confirmed findings | 3 |
| Highest severity | High |

All three tested pages on Juice Shop are missing a **Content-Security-Policy** header. **X-Frame-Options** is correctly configured (`SAMEORIGIN`) on all three, so no clickjacking finding was raised. **HSTS** was not applicable, as the instance is served over plain HTTP in this local lab setup.

## 5. Detailed Findings

| URL | Header | Status | Severity | Evidence |
|---|---|---|---|---|
| http://localhost:3000/ | Content-Security-Policy | Missing | High | Header not present in response (confirmed on retest) |
| http://localhost:3000/#/login | Content-Security-Policy | Missing | High | Header not present in response (confirmed on retest) |
| http://localhost:3000/#/search | Content-Security-Policy | Missing | High | Header not present in response (confirmed on retest) |

*(X-Frame-Options and HSTS omitted from this table — both returned no finding: X-Frame-Options was present and correctly configured, and HSTS is not applicable over plain HTTP.)*

## 6. Remediation

- **Content-Security-Policy**: Add a restrictive policy such as `Content-Security-Policy: default-src 'self'; script-src 'self'` at the web server or application level. Start in `Content-Security-Policy-Report-Only` mode to identify any legitimate resources the policy would block before enforcing it, then tighten and enforce.
- No action needed for X-Frame-Options — already correctly set to `SAMEORIGIN`.
- No action needed for HSTS in this local lab context; if this application were deployed over HTTPS in production, `Strict-Transport-Security: max-age=31536000; includeSubDomains` should be added at that time.

## 7. Tool Documentation

**How it works:** `header_scanner.py` takes a text file of URLs (or a single `--url`), performs a GET request against each, and evaluates the three target headers using the logic in Section 3. Results are written to both a machine-readable `report.json` and a human-readable `report.md`.

**Usage:**
```
python header_scanner.py --urls urls.txt --json report.json --md report.md
```

**Known Limitations:**
- Checks header *presence and basic configuration* only — it does not verify that a CSP policy's specific allowed sources are correct for the application's actual scripts/styles, only that a policy exists and avoids obviously weak keywords.
- HSTS is marked not-applicable on plain HTTP targets rather than flagged as a finding, since the header has no effect there.
- The confirmation step is a same-tool second request with a short delay; it does not account for headers that vary by request path, user-agent, or authentication state.
- The tool does not crawl the application automatically — it only checks the exact URLs supplied in the input list.

## 8. Confirmation of Authorized Testing

All testing described in this report was performed solely against a locally-hosted OWASP Juice Shop instance running on the tester's own machine, with no external or production systems accessed at any point.
