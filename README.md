# security-headers-scanner
# Missing Security Headers Detection Tool

A Python scanner that checks a list of authorized URLs for missing or weakly-configured HTTP security headers-Content-Security-Policy (CSP), Strict-Transport-Security (HSTS), and X-Frame-Options and generates a professional findings report.

## Project

SafeX Internship "Week 4"

## What It Checks

- **Content-Security-Policy**: flags if missing, or if present but containing weak directives (`unsafe-inline`, `unsafe-eval`, wildcard sources)
- **Strict-Transport-Security**: flags if missing on HTTPS targets (not applicable over plain HTTP); flags if `max-age` is too short
- **X-Frame-Options**: flags if missing, unless an equivalent CSP `frame-ancestors` directive is present

Every "missing" result is confirmed with a second independent request before being reported, to reduce false positives.

## Usage

Or scan a single URL:http://localhost:3000/

## Validation

The tool was tested against two local mock servers during development one with no security headers (confirmed true-positive detection) and one with correctly-configured headers (confirmed zero false positives) before being run against the live lab target.

## Target Tested

OWASP Juice Shop, run locally via Docker (`http://localhost:3000`)  no external or production systems were scanned.

## Full Report

See [security_report.md](./security_report.md) for the complete findings, evidence, severity ratings, remediation guidance, and known limitations.

## Known Limitations

- Checks header presence and basic configuration only does not verify a CSP policy's specific allowed sources are correct for the app
- HSTS is skipped (not flagged) on plain HTTP targets, since the header has no effect there
- Does not crawl the application only checks the exact URLs provided in the input list

## Author

 YusraAhmad, SafeX Internship, Week 4
