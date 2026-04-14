import argparse
import asyncio
import sys
import os
import json

sys.path.insert(0, os.path.dirname(__file__))

import httpx
from parser.swagger import parse_swagger
from parser.crawler import crawl
from auth.handler import AuthHandler, login
from tests.bola import run_bola_test
from tests.auth_bypass import run_auth_bypass_test
from tests.mass_assign import run_mass_assignment_test
from tests.rate_limit import run_rate_limit_test
from tests.data_exposure import run_data_exposure_test
from tests.graphql import run_graphql_test
from reporter.report import generate_report


async def run(args):
    print(f"[*] Target: {args.url}")

    # Auto-login for token1
    if args.login_url:
        if not args.username or not args.password:
            raise SystemExit("[!] --login-url requires --username and --password")
        print(f"[*] Logging in via {args.login_url} ...")
        args.token1 = login(args.login_url, args.username, args.password)
        print(f"[*] Token1 acquired: {args.token1[:40]}...")

    # Auto-login for token2
    if args.login_url2:
        if not args.username2 or not args.password2:
            raise SystemExit("[!] --login-url2 requires --username2 and --password2")
        print(f"[*] Logging in user2 via {args.login_url2} ...")
        args.token2 = login(args.login_url2, args.username2, args.password2)
        print(f"[*] Token2 acquired: {args.token2[:40]}...")

    if args.swagger:
        print(f"[*] Parsing Swagger: {args.swagger}")
        endpoints = parse_swagger(args.swagger)
    else:
        print("[*] No Swagger file — crawling JS files to discover endpoints...")
        endpoints = await crawl(args.url, token=args.token1)

    print(f"[*] Loaded {len(endpoints)} endpoints")

    auth = AuthHandler(token1=args.token1, token2=args.token2)
    all_findings = []

    async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
        tests = [
            ("bola",     lambda: run_bola_test(args.url, endpoints, auth, client),            "BOLA/IDOR"),
            ("auth",     lambda: run_auth_bypass_test(args.url, endpoints, auth, client),     "Auth Bypass"),
            ("mass",     lambda: run_mass_assignment_test(args.url, endpoints, auth, client), "Mass Assignment"),
            ("rate",     lambda: run_rate_limit_test(args.url, endpoints, auth, client),      "Rate Limiting"),
            ("exposure", lambda: run_data_exposure_test(args.url, endpoints, auth, client),   "Data Exposure"),
            ("graphql",  lambda: run_graphql_test(args.url, auth, client),                    "GraphQL"),
        ]

        skip = args.skip or []
        tasks = {}
        for key, fn, label in tests:
            if key not in skip:
                tasks[label] = fn()

        results = await asyncio.gather(*tasks.values(), return_exceptions=True)

        for label, result in zip(tasks.keys(), results):
            if isinstance(result, Exception):
                print(f"[!] {label} error: {result}")
            else:
                print(f"[*] {label}: {len(result)} issue(s) found")
                all_findings.extend(result)

    print(f"\n[+] Total findings: {len(all_findings)}")

    # Apply severity filter
    severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    min_level = severity_order.get(args.min_severity.upper(), 1)
    filtered = [f for f in all_findings if severity_order.get(f.get("severity", "LOW"), 1) >= min_level]
    if args.min_severity.upper() != "LOW":
        print(f"[*] Showing {len(filtered)} findings at {args.min_severity.upper()} or above")

    if args.format == "json":
        out = args.output.replace(".html", ".json") if args.output.endswith(".html") else args.output
        with open(out, "w") as f:
            json.dump(filtered, f, indent=2)
        print(f"[+] JSON report saved → {out}")
    else:
        generate_report(filtered, args.output, args.url)

    # Exit 1 if any HIGH or CRITICAL found (for CI/CD pipelines)
    critical_count = sum(1 for f in all_findings if f.get("severity") in ("CRITICAL", "HIGH"))
    if critical_count:
        print(f"[!] {critical_count} HIGH/CRITICAL issue(s) found — exiting with code 1")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="API Security Tester")
    parser.add_argument("--swagger",    help="Path to Swagger/OpenAPI file")
    parser.add_argument("--url",        required=True, help="Base API URL (e.g. https://api.example.com)")
    parser.add_argument("--token1",     default=None,  help="JWT token for user 1 (e.g. 'Bearer eyJ...')")
    parser.add_argument("--token2",     help="JWT token for user 2 (optional, for BOLA cross-user testing)")
    parser.add_argument("--login-url",  help="Login endpoint to auto-fetch token1")
    parser.add_argument("--username",   help="Username/email for auto-login (token1)")
    parser.add_argument("--password",   help="Password for auto-login (token1)")
    parser.add_argument("--login-url2", help="Login endpoint to auto-fetch token2")
    parser.add_argument("--username2",  help="Username/email for auto-login (token2)")
    parser.add_argument("--password2",  help="Password for auto-login (token2)")
    parser.add_argument("--output",     default="report.html", help="Output report file")
    parser.add_argument("--format",     choices=["html", "json"], default="html", help="Output format (default: html)")
    parser.add_argument("--min-severity", default="low", choices=["low","medium","high","critical"], help="Minimum severity to include in report (default: low)")
    parser.add_argument("--skip",       nargs="*", default=[], help="Tests to skip: bola auth mass rate exposure graphql")
    args = parser.parse_args()

    if not args.token1 and not args.login_url:
        raise SystemExit("[!] Provide either --token1 or --login-url + --username + --password")

    asyncio.run(run(args))


if __name__ == "__main__":
    main()
