import re
import httpx

ID_PATTERN = re.compile(r"(\b\d{3,}\b|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})")
HAS_ID_SEGMENT = re.compile(r"/(\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|\{[^}]+\}|:[a-z_]+)(/|$)")

# Swagger path param placeholder — e.g. {petId}, {id}, {userId}
SWAGGER_PARAM = re.compile(r"\{([^}]+)\}")


def _resolve_swagger_params(path: str) -> list[str]:
    """Replace {param} placeholders with candidate real IDs to test."""
    if not SWAGGER_PARAM.search(path):
        return [path]
    candidates = []
    for test_id in ("1", "2", "3", "100"):
        candidates.append(SWAGGER_PARAM.sub(test_id, path))
    return candidates


def _collect_ids_from_response(text: str) -> list[str]:
    return list(set(ID_PATTERN.findall(text)))


def _generate_neighbors(id_val: str) -> list[str]:
    try:
        n = int(id_val)
        return [str(n - 2), str(n - 1), str(n + 1), str(n + 2)]
    except ValueError:
        return []


async def run_bola_test(base_url: str, endpoints: list[dict], auth, client: httpx.AsyncClient) -> list[dict]:
    findings = []

    for ep in endpoints:
        if ep["method"] not in ("GET", "PUT", "DELETE"):
            continue
        if not HAS_ID_SEGMENT.search(ep["path"]):
            continue

        # Resolve Swagger {param} placeholders into real candidate paths
        resolved_paths = _resolve_swagger_params(ep["path"])

        for resolved_path in resolved_paths:
            url = base_url.rstrip("/") + resolved_path

            try:
                r1 = await client.request(ep["method"], url, headers=auth.headers(auth.token1))
                if r1.status_code not in (200, 201):
                    continue

                if auth.token2:
                    r2 = await client.request(ep["method"], url, headers=auth.headers(auth.token2))
                    if r2.status_code == 200 and abs(len(r1.content) - len(r2.content)) < 50 and len(r1.content) > 10:
                        findings.append({
                            "type": "BOLA/IDOR",
                            "severity": "CRITICAL",
                            "endpoint": f"{ep['method']} {resolved_path}",
                            "detail": f"User B accessed User A's resource. Response sizes: A={len(r1.content)}B, B={len(r2.content)}B",
                            "request": f"{ep['method']} {url} [token2]",
                            "request_headers": dict(auth.headers(auth.token2)),
                            "response_body": r2.text[:500],
                            "status_code": r2.status_code,
                        })
                        continue

                for found_id in _collect_ids_from_response(r1.text)[:5]:
                    for test_id in _generate_neighbors(found_id):
                        if found_id not in resolved_path:
                            continue
                        test_path = resolved_path.replace(found_id, test_id, 1)
                        test_url = base_url.rstrip("/") + test_path
                        r_enum = await client.request(ep["method"], test_url, headers=auth.headers(auth.token1))
                        if r_enum.status_code == 200 and len(r_enum.content) > 10:
                            findings.append({
                                "type": "BOLA/IDOR (ID Enumeration)",
                                "severity": "HIGH",
                                "endpoint": f"{ep['method']} {test_path}",
                                "detail": f"Accessed neighbor ID {test_id} (found ID {found_id} in your response).",
                                "request": f"{ep['method']} {test_url} [token1]",
                                "request_headers": dict(auth.headers(auth.token1)),
                                "response_body": r_enum.text[:500],
                                "status_code": r_enum.status_code,
                            })
            except httpx.RequestError:
                continue

    return findings
