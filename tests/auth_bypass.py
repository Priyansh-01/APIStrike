import re
import httpx

# Endpoints that are legitimately public — no auth required by design
PUBLIC_PATH_PATTERN = re.compile(
    r"/(login|logout|signin|signup|register|health|ping|status|oauth|token|refresh|forgot|reset|verify|confirm)(/|$)",
    re.IGNORECASE,
)


async def run_auth_bypass_test(base_url: str, endpoints: list[dict], auth, client: httpx.AsyncClient) -> list[dict]:
    findings = []

    for ep in endpoints:
        # Skip endpoints that are inherently public
        if PUBLIC_PATH_PATTERN.search(ep["path"]):
            continue

        url = base_url.rstrip("/") + ep["path"]
        method = ep["method"]

        try:
            baseline = await client.request(method, url, headers=auth.headers(auth.token1))
            # Skip if even the authenticated request doesn't return 200 (endpoint may need a body/params)
            if baseline.status_code not in (200, 201):
                continue

            tests = [
                ("No Token",       {}),
                ("Expired JWT",    auth.headers(auth.expired_jwt(auth.token1))),
                ("Alg:None JWT",   auth.headers(auth.tampered_jwt(auth.token1))),
                ("Admin Role JWT", auth.headers(auth.admin_jwt(auth.token1))),
            ]

            for label, headers in tests:
                r = await client.request(method, url, headers=headers)
                # Skip if response is identical to authenticated — endpoint is just public by design
                if r.status_code == 200 and r.text == baseline.text:
                    continue
                if r.status_code == 200:
                    findings.append({
                        "type": "Auth Bypass",
                        "severity": "CRITICAL" if "Admin" in label else "HIGH",
                        "endpoint": f"{method} {ep['path']}",
                        "detail": f"{label} returned 200 OK — should be 401/403.",
                        "request": f"{method} {url} [{label}]",
                        "request_headers": headers,
                        "response_body": r.text[:500],
                        "status_code": r.status_code,
                    })
        except httpx.RequestError:
            continue

    return findings
