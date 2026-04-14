import asyncio
import httpx
from config import RATE_LIMIT_COUNT, RATE_LIMIT_ENDPOINTS


async def run_rate_limit_test(base_url: str, endpoints: list[dict], auth, client: httpx.AsyncClient) -> list[dict]:
    findings = []

    targets = [ep for ep in endpoints if any(kw in ep["path"].lower() for kw in RATE_LIMIT_ENDPOINTS)]

    for ep in targets:
        url = base_url.rstrip("/") + ep["path"]
        headers = auth.headers(auth.token1)

        # Fire all requests concurrently as a burst
        tasks = [client.request(ep["method"], url, headers=headers) for _ in range(RATE_LIMIT_COUNT)]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        blocked = any(
            not isinstance(r, Exception) and r.status_code in (429, 403)
            for r in results
        )

        if not blocked:
            findings.append({
                "type": "Missing Rate Limiting",
                "severity": "MEDIUM",
                "endpoint": f"{ep['method']} {ep['path']}",
                "detail": f"Burst of {RATE_LIMIT_COUNT} concurrent requests — no 429/block response received.",
                "request": f"{ep['method']} {url}",
                "request_headers": headers,
                "response_body": "N/A",
                "status_code": "No block",
            })

    return findings
