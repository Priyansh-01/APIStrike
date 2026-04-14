import re
import asyncio
from urllib.parse import urlparse, urljoin

try:
    from playwright.async_api import async_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

# Broader pattern — captures /api/, /rest/, /v1/-/v9/, /graphql, /gql, /rpc, /service, /services
API_PATH_RE = re.compile(
    r"^/(api|rest|gql|graphql|rpc|service[s]?|v\d+)/", re.IGNORECASE
)

# Common REST base paths to probe when crawl finds nothing — "" means root level
COMMON_REST_BASES = [
    "", "/api", "/api/v1", "/api/v2", "/rest", "/rest/v1",
    "/v1", "/v2", "/v3",
]

# Common resource names to try under each base
COMMON_RESOURCES = [
    "users", "user", "products", "product", "orders", "order",
    "items", "posts", "comments", "accounts", "profile",
    "customers", "articles", "categories", "search",
    "todos", "albums", "photos", "employees", "suppliers",
]


async def crawl(base_url: str, token: str = None, use_browser: bool = True) -> list[dict]:
    if use_browser and PLAYWRIGHT_AVAILABLE:
        try:
            endpoints = await _crawl_with_browser(base_url, token)
        except Exception as e:
            print(f"[!] Browser crawl failed: {e}. Falling back to regex crawl.")
            endpoints = await asyncio.get_event_loop().run_in_executor(None, _crawl_with_regex, base_url, token)
    else:
        if use_browser:
            print("[!] Playwright not installed. Install with: pip install playwright && playwright install chromium")
        endpoints = await asyncio.get_event_loop().run_in_executor(None, _crawl_with_regex, base_url, token)

    # If crawl found nothing, probe common REST paths
    if not endpoints:
        print("[*] No endpoints discovered — probing common REST paths...")
        endpoints = await asyncio.get_event_loop().run_in_executor(None, _probe_common_paths, base_url, token)

    return endpoints


async def _crawl_with_browser(base_url: str, token: str = None) -> list[dict]:
    found_paths = set()

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context()

        if token:
            await context.set_extra_http_headers({"Authorization": token})

        page = await context.new_page()

        def handle_request(request):
            parsed = urlparse(request.url)
            # Only capture same-host requests matching API path pattern
            if urlparse(base_url).netloc == parsed.netloc and API_PATH_RE.match(parsed.path):
                found_paths.add(parsed.path.split("?")[0])

        page.on("request", handle_request)

        try:
            await page.goto(base_url, wait_until="networkidle", timeout=15000)
            await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
            await page.wait_for_timeout(2000)
        except Exception as e:
            print(f"[!] Browser crawl warning: {e}")

        await browser.close()

    return _build_endpoints(found_paths, "Browser crawl")


def _crawl_with_regex(base_url: str, token: str = None) -> list[dict]:
    import httpx

    # Broader regex — matches /api/, /rest/, /v1-v9/, /graphql, /gql, /rpc, /services
    API_PATTERN = re.compile(
        r'["\'`]((?:/api|/rest|/gql|/graphql|/rpc|/services?|/v\d+)/[^\s"\'`?#]*)["\' `]'
    )
    JS_SRC_PATTERN = re.compile(r'<script[^>]+src=["\'](.*?\.js.*?)["\']', re.IGNORECASE)

    headers = {"Authorization": token} if token else {}
    found_paths = set()

    with httpx.Client(headers=headers, timeout=10, follow_redirects=True) as session:
        try:
            root = session.get(base_url)
            js_urls = set()
            for src in JS_SRC_PATTERN.findall(root.text):
                js_urls.add(urljoin(base_url, src) if not src.startswith("http") else src)

            for path in ["/static/js/main.js", "/assets/index.js", "/app.js", "/bundle.js",
                         "/main.js", "/static/js/bundle.js", "/js/app.js"]:
                js_urls.add(urljoin(base_url, path))

            for js_url in js_urls:
                try:
                    r = session.get(js_url)
                    if r.status_code == 200:
                        found_paths.update(API_PATTERN.findall(r.text))
                except httpx.RequestError:
                    continue
        except httpx.RequestError as e:
            print(f"[!] Regex crawl failed: {e}")

    return _build_endpoints(found_paths, "Regex crawl")


def _get_catchall_fingerprint(session, base_url: str) -> str | None:
    """GET a guaranteed-nonexistent path and return its body as a catch-all fingerprint."""
    try:
        r = session.get(base_url.rstrip("/") + "/__probe_nonexistent_xyz123__")
        if r.status_code in (401, 403, 404):
            return r.text.strip()
    except Exception:
        pass
    return None


def _is_real_endpoint(response, catchall_body: str | None) -> bool:
    """Return True if the response looks like a real endpoint, not a catch-all."""
    if response.status_code not in (200, 201, 401, 403):
        return False
    # If body matches the catch-all fingerprint, it's not a real endpoint
    if catchall_body and response.text.strip() == catchall_body:
        return False
    if response.status_code in (200, 201):
        return _is_meaningful_json(response)
    return True  # 401/403 with a unique body = real protected endpoint


def _is_meaningful_json(response) -> bool:
    """Return True only if response is a non-empty JSON array or object with keys."""
    try:
        data = response.json()
        if isinstance(data, list):
            return len(data) > 0
        if isinstance(data, dict):
            return len(data) > 0
    except Exception:
        pass
    return False


def _probe_common_paths(base_url: str, token: str = None) -> list[dict]:
    """Actively probe common REST base paths and resource names."""
    import httpx

    headers = {"Authorization": token} if token else {}
    found_paths = set()

    with httpx.Client(headers=headers, timeout=8, follow_redirects=True) as session:
        # Fingerprint the catch-all error response (if any) to filter false 401s
        catchall_body = _get_catchall_fingerprint(session, base_url)

        for base in COMMON_REST_BASES:
            for resource in COMMON_RESOURCES:
                path = f"{base}/{resource}" if base else f"/{resource}"
                try:
                    r = session.get(base_url.rstrip("/") + path)
                    if _is_real_endpoint(r, catchall_body):
                        found_paths.add(path)
                        try:
                            r2 = session.get(base_url.rstrip("/") + path + "/1")
                            if _is_real_endpoint(r2, catchall_body):
                                found_paths.add(path + "/1")
                        except httpx.RequestError:
                            pass
                except httpx.RequestError:
                    continue

    return _build_endpoints(found_paths, "Path probe")


def _build_endpoints(paths: set, source: str) -> list[dict]:
    endpoints = []
    seen = set()

    for path in sorted(paths):
        clean = path.split("?")[0].rstrip("/")
        if not clean or clean in seen:
            continue
        seen.add(clean)

        has_id = bool(re.search(r"/\d+|/\{|/:|\bme\b", clean))
        methods = ["GET", "PUT", "DELETE"] if has_id else ["GET", "POST"]

        for method in methods:
            endpoints.append({
                "method": method,
                "path": clean,
                "params": [],
                "summary": f"Discovered via {source}",
            })

    print(f"[*] {source} found {len(seen)} unique paths → {len(endpoints)} endpoint entries")
    return endpoints
