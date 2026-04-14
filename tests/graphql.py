import httpx


INTROSPECTION_QUERY = """
{
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      kind
      fields {
        name
        args { name type { name kind ofType { name kind } } }
        type { name kind ofType { name kind } }
      }
    }
  }
}
"""

BATCH_ATTACK = [
    {"query": "{ __typename }"},
    {"query": "{ __typename }"},
    {"query": "{ __typename }"},
]


async def run_graphql_test(base_url: str, auth, client: httpx.AsyncClient) -> list[dict]:
    findings = []

    # Common GraphQL endpoint paths
    candidates = ["/graphql", "/api/graphql", "/v1/graphql", "/query", "/gql"]

    gql_url = None
    for path in candidates:
        url = base_url.rstrip("/") + path
        try:
            r = await client.post(url, json={"query": "{ __typename }"}, headers=auth.headers(auth.token1))
            if r.status_code == 200 and "__typename" in r.text:
                gql_url = url
                print(f"[*] GraphQL endpoint found: {gql_url}")
                break
        except httpx.RequestError:
            continue

    if not gql_url:
        print("[*] No GraphQL endpoint detected.")
        return []

    headers1 = auth.headers(auth.token1)

    # Test 1: Introspection enabled (leaks full schema — should be disabled in prod)
    try:
        r = await client.post(gql_url, json={"query": INTROSPECTION_QUERY}, headers=headers1)
        if r.status_code == 200 and "queryType" in r.text:
            findings.append({
                "type": "GraphQL Introspection Enabled",
                "severity": "MEDIUM",
                "endpoint": f"POST {gql_url}",
                "detail": "Introspection is enabled — full schema is exposed. Attackers can map every query, mutation, and field.",
                "request": f"POST {gql_url}\nBody: introspection query",
                "request_headers": headers1,
                "response_body": r.text[:500],
                "status_code": r.status_code,
            })
            findings.extend(_test_idor_from_schema(r.text, gql_url, headers1))

    except httpx.RequestError:
        pass

    # Test 2: Batching attack (send many queries in one request — bypasses rate limiting)
    try:
        r = await client.post(gql_url, json=BATCH_ATTACK, headers=headers1)
        if r.status_code == 200 and isinstance(r.json(), list):
            findings.append({
                "type": "GraphQL Batching Attack",
                "severity": "MEDIUM",
                "endpoint": f"POST {gql_url}",
                "detail": "Server accepts batched queries. Can be used to bypass rate limiting on login/OTP mutations.",
                "request": f"POST {gql_url}\nBody: array of queries",
                "request_headers": headers1,
                "response_body": r.text[:500],
                "status_code": r.status_code,
            })
    except httpx.RequestError:
        pass

    # Test 3: Auth bypass — query without token
    try:
        r = await client.post(gql_url, json={"query": "{ __typename }"}, headers={})
        if r.status_code == 200 and "__typename" in r.text:
            findings.append({
                "type": "GraphQL Auth Bypass",
                "severity": "HIGH",
                "endpoint": f"POST {gql_url}",
                "detail": "GraphQL endpoint responds without any authentication token.",
                "request": f"POST {gql_url} [no token]",
                "request_headers": {},
                "response_body": r.text[:500],
                "status_code": r.status_code,
            })
    except httpx.RequestError:
        pass

    # Test 4: Field suggestion (server hints at valid field names — info leak)
    try:
        r = await client.post(gql_url, json={"query": '{ usr { id } }'}, headers=headers1)
        if "Did you mean" in r.text or "suggestion" in r.text.lower():
            findings.append({
                "type": "GraphQL Field Suggestion Enabled",
                "severity": "LOW",
                "endpoint": f"POST {gql_url}",
                "detail": "Server returns field name suggestions on typos — leaks valid field names even without introspection.",
                "request": f"POST {gql_url}\nBody: {{usr {{id}}}}",
                "request_headers": headers1,
                "response_body": r.text[:300],
                "status_code": r.status_code,
            })
    except httpx.RequestError:
        pass

    return findings


def _test_idor_from_schema(schema_text: str, gql_url: str, headers: dict) -> list[dict]:
    """Look for queries that take an ID argument — potential IDOR."""
    import re
    findings = []
    id_queries = re.findall(r'"name"\s*:\s*"(\w+)".*?"args".*?"name"\s*:\s*"id"', schema_text)
    for q in id_queries[:3]:
        findings.append({
            "type": "GraphQL Potential IDOR",
            "severity": "HIGH",
            "endpoint": f"POST {gql_url}",
            "detail": f"Query '{q}' accepts an 'id' argument — test manually for IDOR by changing the ID value.",
            "request": f'POST {gql_url}\nBody: {{ {q}(id: 1) {{ ... }} }}',
            "request_headers": headers,
            "response_body": "Manual verification required",
            "status_code": "N/A",
        })
    return findings
