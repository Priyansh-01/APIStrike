import json
import yaml
from urllib.parse import urlparse


def parse_swagger(file_path: str) -> list[dict]:
    """Parse a Swagger/OpenAPI v2 or v3 file and return a list of endpoints."""
    with open(file_path, "r") as f:
        spec = json.load(f) if file_path.endswith(".json") else yaml.safe_load(f)

    # OpenAPI v3: base path comes from servers[0].url (path component only)
    if "openapi" in spec:
        servers = spec.get("servers", [{}])
        server_url = servers[0].get("url", "") if servers else ""
        base_path = urlparse(server_url).path.rstrip("/") if server_url.startswith("http") else server_url.rstrip("/")
    else:
        base_path = spec.get("basePath", "") or ""

    endpoints = []
    for path, methods in spec.get("paths", {}).items():
        for method, details in methods.items():
            if method.lower() in ("get", "post", "put", "patch", "delete"):
                params = []
                for p in details.get("parameters", []):
                    params.append({
                        "name": p.get("name"),
                        "in": p.get("in"),
                        "required": p.get("required", False),
                        "type": p.get("schema", {}).get("type", p.get("type", "string")),
                    })
                endpoints.append({
                    "method": method.upper(),
                    "path": base_path + path,
                    "params": params,
                    "summary": details.get("summary", ""),
                })

    return endpoints
