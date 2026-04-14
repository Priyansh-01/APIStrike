import httpx
from config import SENSITIVE_FIELDS


async def run_mass_assignment_test(base_url: str, endpoints: list[dict], auth, client: httpx.AsyncClient) -> list[dict]:
    findings = []

    for ep in [e for e in endpoints if e["method"] in ("POST", "PUT", "PATCH")]:
        url = base_url.rstrip("/") + ep["path"]
        injected_body = {field: "pwned_test_value" for field in SENSITIVE_FIELDS}
        headers = auth.headers(auth.token1)

        try:
            # Baseline: send empty body to see what the API normally echoes back
            baseline = await client.request(ep["method"], url, json={}, headers=headers)

            r = await client.request(ep["method"], url, json=injected_body, headers=headers)

            # Only flag if:
            # 1. The sentinel value appears in the response AND
            # 2. The response is different from baseline (not just a generic echo-all mock)
            reflected = [f for f in SENSITIVE_FIELDS if f.lower() in r.text.lower() and "pwned_test_value" in r.text]
            # If baseline with empty body returns a tiny response (just an id), it's a mock echo API
            is_echo_api = (
                baseline.status_code in (200, 201) and
                len(baseline.text.strip()) < 30  # empty-body response is tiny → pure echo
            ) or (
                abs(len(baseline.text) - len(r.text)) < 50 and len(baseline.text) > 0
            )

            if reflected and not is_echo_api:
                findings.append({
                    "type": "Mass Assignment",
                    "severity": "HIGH",
                    "endpoint": f"{ep['method']} {ep['path']}",
                    "detail": f"Injected fields reflected in response: {reflected}",
                    "request": f"{ep['method']} {url}\nBody: {injected_body}",
                    "request_headers": headers,
                    "response_body": r.text[:500],
                    "status_code": r.status_code,
                })
        except httpx.RequestError:
            continue

    return findings
