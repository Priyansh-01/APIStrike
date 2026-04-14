import re
import httpx
from config import SENSITIVE_PATTERNS


async def run_data_exposure_test(base_url: str, endpoints: list[dict], auth, client: httpx.AsyncClient) -> list[dict]:
    findings = []

    for ep in endpoints:
        url = base_url.rstrip("/") + ep["path"]
        headers = auth.headers(auth.token1)
        try:
            r = await client.request(ep["method"], url, headers=headers)
            for label, pattern in SENSITIVE_PATTERNS.items():
                matches = re.findall(pattern, r.text)
                if matches:
                    findings.append({
                        "type": "Sensitive Data Exposure",
                        "severity": "HIGH",
                        "endpoint": f"{ep['method']} {ep['path']}",
                        "detail": f"Pattern '{label}' found. Sample: {matches[0][:60]}",
                        "request": f"{ep['method']} {url}",
                        "request_headers": headers,
                        "response_body": r.text[:500],
                        "status_code": r.status_code,
                    })
        except httpx.RequestError:
            continue

    return findings
