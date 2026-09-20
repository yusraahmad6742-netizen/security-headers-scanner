#!/usr/bin/env python3
"""
Missing Security Headers Detection Tool
Checks a list of AUTHORIZED lab URLs for missing/weak CSP, HSTS,
and X-Frame-Options headers, and produces a findings report.

Intended for use only against systems you own or are explicitly
authorized to test (e.g. a locally-run OWASP Juice Shop instance).

Usage:
    python header_scanner.py --urls urls.txt --json report.json --md report.md
    python header_scanner.py --url http://localhost:3000/
"""

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

TIMEOUT = 8
CONFIRM_DELAY_SECONDS = 1  # gap between the two confirmation requests


# --------------------------------------------------------------------------
# Detection logic
# --------------------------------------------------------------------------

def fetch_headers(url):
    """Fetch response headers for a URL. Returns (headers, error)."""
    try:
        resp = requests.get(url, timeout=TIMEOUT, allow_redirects=True)
        return resp.headers, None
    except requests.RequestException as exc:
        return None, str(exc)


def confirm_missing(url, header_name):
    """
    Re-check a single header on a second, separate request to rule out
    a one-off network blip or a load balancer serving a different node.
    Returns True if the header is missing on BOTH requests (confirmed).
    """
    time.sleep(CONFIRM_DELAY_SECONDS)
    headers, err = fetch_headers(url)
    if err:
        # Could not confirm — treat as unconfirmed rather than a false positive
        return False
    return header_name not in headers


def evaluate_csp(headers, url):
    """Check Content-Security-Policy presence and obvious weak configs."""
    csp = headers.get("Content-Security-Policy")
    if csp is None:
        confirmed = confirm_missing(url, "Content-Security-Policy")
        return {
            "header": "Content-Security-Policy",
            "status": "missing" if confirmed else "missing (unconfirmed)",
            "evidence": "Header not present in response (confirmed on retest)."
                        if confirmed else "Header not present; retest inconclusive.",
            "severity": "High",
        }

    weak_signatures = ["unsafe-inline", "unsafe-eval", "*"]
    weak_hits = [sig for sig in weak_signatures if sig in csp]
    if weak_hits:
        return {
            "header": "Content-Security-Policy",
            "status": "weak",
            "evidence": f"Policy present but contains weak directive(s): {', '.join(weak_hits)}. "
                        f"Full value: {csp}",
            "severity": "Medium",
        }

    return {
        "header": "Content-Security-Policy",
        "status": "present",
        "evidence": f"Policy present: {csp}",
        "severity": "N/A",
    }


def evaluate_hsts(headers, url):
    """Check Strict-Transport-Security. Only meaningful over HTTPS."""
    scheme = urlparse(url).scheme
    if scheme != "https":
        return {
            "header": "Strict-Transport-Security",
            "status": "not_applicable",
            "evidence": "Target served over plain HTTP, so HSTS does not apply here. "
                        "Note: serving sensitive functionality over HTTP at all is a "
                        "separate finding worth flagging manually.",
            "severity": "N/A",
        }

    hsts = headers.get("Strict-Transport-Security")
    if hsts is None:
        confirmed = confirm_missing(url, "Strict-Transport-Security")
        return {
            "header": "Strict-Transport-Security",
            "status": "missing" if confirmed else "missing (unconfirmed)",
            "evidence": "Header not present on an HTTPS response (confirmed on retest)."
                        if confirmed else "Header not present; retest inconclusive.",
            "severity": "Medium",
        }

    max_age_ok = "max-age=" in hsts and _extract_max_age(hsts) >= 15552000  # ~6 months
    if not max_age_ok:
        return {
            "header": "Strict-Transport-Security",
            "status": "weak",
            "evidence": f"Header present but max-age is short or missing: {hsts}",
            "severity": "Low",
        }

    return {
        "header": "Strict-Transport-Security",
        "status": "present",
        "evidence": f"Header present: {hsts}",
        "severity": "N/A",
    }


def _extract_max_age(hsts_value):
    try:
        part = [p for p in hsts_value.split(";") if "max-age=" in p][0]
        return int(part.split("=")[1].strip())
    except (IndexError, ValueError):
        return 0


def evaluate_xfo(headers, url):
    """
    Check X-Frame-Options, or an equivalent CSP frame-ancestors directive
    (which supersedes X-Frame-Options in modern browsers).
    """
    xfo = headers.get("X-Frame-Options")
    csp = headers.get("Content-Security-Policy", "")
    has_frame_ancestors = "frame-ancestors" in csp

    if xfo is None and not has_frame_ancestors:
        confirmed = confirm_missing(url, "X-Frame-Options")
        return {
            "header": "X-Frame-Options",
            "status": "missing" if confirmed else "missing (unconfirmed)",
            "evidence": "Neither X-Frame-Options nor CSP frame-ancestors present "
                        "(confirmed on retest); page can likely be framed by any origin."
                        if confirmed else "Header not present; retest inconclusive.",
            "severity": "Medium",
        }

    if has_frame_ancestors:
        return {
            "header": "X-Frame-Options",
            "status": "present (via CSP frame-ancestors)",
            "evidence": "Clickjacking protection provided by CSP frame-ancestors directive.",
            "severity": "N/A",
        }

    if xfo.upper() not in ("DENY", "SAMEORIGIN"):
        return {
            "header": "X-Frame-Options",
            "status": "weak",
            "evidence": f"Header present but value is non-standard: {xfo}",
            "severity": "Low",
        }

    return {
        "header": "X-Frame-Options",
        "status": "present",
        "evidence": f"Header present: {xfo}",
        "severity": "N/A",
    }


def scan_url(url):
    """Run all three checks against a single URL."""
    headers, err = fetch_headers(url)
    timestamp = datetime.now(timezone.utc).isoformat()

    if err:
        return {
            "url": url,
            "timestamp": timestamp,
            "reachable": False,
            "error": err,
            "findings": [],
        }

    findings = [
        evaluate_csp(headers, url),
        evaluate_hsts(headers, url),
        evaluate_xfo(headers, url),
    ]

    return {
        "url": url,
        "timestamp": timestamp,
        "reachable": True,
        "error": None,
        "findings": findings,
    }


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------

def build_markdown_report(results):
    lines = []
    lines.append("# Missing Security Headers — Findings Report")
    lines.append("")
    lines.append(f"Generated: {datetime.now(timezone.utc).isoformat()}")
    lines.append("")
    lines.append("**Scope:** Only authorized/lab systems were tested "
                  "(local OWASP Juice Shop instance and comparison targets "
                  "chosen for benign, passive header inspection only).")
    lines.append("")

    total_findings = sum(
        1 for r in results for f in r["findings"]
        if f["status"] in ("missing", "missing (unconfirmed)", "weak")
    )
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- URLs scanned: {len(results)}")
    lines.append(f"- Total findings (missing/weak headers): {total_findings}")
    lines.append("")

    lines.append("## Findings")
    lines.append("")
    lines.append("| URL | Header | Status | Severity | Evidence |")
    lines.append("|---|---|---|---|---|")

    for r in results:
        if not r["reachable"]:
            lines.append(f"| {r['url']} | — | unreachable | — | {r['error']} |")
            continue
        for f in r["findings"]:
            if f["status"] == "N/A" or f["status"] == "not_applicable":
                continue
            lines.append(
                f"| {r['url']} | {f['header']} | {f['status']} | "
                f"{f['severity']} | {f['evidence']} |"
            )

    lines.append("")
    lines.append("## Remediation Guidance")
    lines.append("")
    lines.append("- **Content-Security-Policy**: Define an allowlist policy, e.g. "
                  "`default-src 'self'; script-src 'self'`, and avoid `unsafe-inline` "
                  "or wildcard sources.")
    lines.append("- **Strict-Transport-Security**: Add `Strict-Transport-Security: "
                  "max-age=31536000; includeSubDomains` on all HTTPS responses.")
    lines.append("- **X-Frame-Options**: Add `X-Frame-Options: SAMEORIGIN`, or a CSP "
                  "`frame-ancestors 'self'` directive, to prevent clickjacking.")
    lines.append("")

    lines.append("## Known Limitations")
    lines.append("")
    lines.append("- Checks header **presence and basic configuration** only — it does not "
                  "verify that a CSP policy is fully correct for the application's actual "
                  "script/style sources, only that it exists and avoids obvious weak keywords.")
    lines.append("- HSTS is marked not-applicable on plain HTTP targets rather than flagged, "
                  "since the header has no effect there; serving the app over HTTP at all is "
                  "a separate, unscored observation.")
    lines.append("- Confirmation is a same-tool second request with a short delay — it does "
                  "not rule out a header being added/removed based on request path, user-agent, "
                  "or authentication state.")
    lines.append("- Does not crawl the application; only checks the exact URLs provided in the "
                  "input list.")
    lines.append("")

    return "\n".join(lines)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def load_urls(path):
    with open(path, "r") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


def main():
    parser = argparse.ArgumentParser(description="Missing Security Headers detection tool")
    parser.add_argument("--urls", help="Path to a text file of URLs, one per line")
    parser.add_argument("--url", help="Scan a single URL instead of a file")
    parser.add_argument("--json", default="report.json", help="Output path for JSON results")
    parser.add_argument("--md", default="report.md", help="Output path for Markdown report")
    args = parser.parse_args()

    if not args.urls and not args.url:
        print("Provide --urls <file> or --url <single URL>", file=sys.stderr)
        sys.exit(1)

    urls = load_urls(args.urls) if args.urls else [args.url]

    results = []
    for url in urls:
        print(f"Scanning {url} ...")
        results.append(scan_url(url))

    with open(args.json, "w") as f:
        json.dump(results, f, indent=2)

    with open(args.md, "w") as f:
        f.write(build_markdown_report(results))

    print(f"\nDone. Wrote {args.json} and {args.md}")


if __name__ == "__main__":
    main()
