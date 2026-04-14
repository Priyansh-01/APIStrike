# APIStrike

A CLI tool that tests REST and GraphQL APIs for common security vulnerabilities. It discovers endpoints via Swagger/OpenAPI spec or by crawling JS files, runs automated tests, and generates a detailed HTML or JSON report.

## Tests Performed

| Test | What it checks |
|------|---------------|
| BOLA/IDOR | Cross-user resource access and ID enumeration |
| Auth Bypass | Endpoints accessible without token, with expired/tampered/alg:none JWT |
| Mass Assignment | Sensitive fields (`role`, `isAdmin`, `balance`, etc.) accepted by POST/PUT |
| Rate Limiting | Login/OTP endpoints that don't block after 100 requests |
| Sensitive Data Exposure | Emails, JWTs, AWS keys, passwords in responses |
| GraphQL | Introspection, batching, auth bypass, field suggestions, IDOR |

## Installation

```bash
pip install -r requirements.txt
playwright install chromium   # optional — enables browser-based crawling
```

## Usage

```bash
# With a Swagger/OpenAPI file
python main.py --url https://api.example.com --swagger openapi.json --token1 "Bearer eyJ..."

# Without Swagger — crawls JS files to discover endpoints
python main.py --url https://api.example.com --token1 "Bearer eyJ..."

# Auto-login (no need to paste a token manually)
python main.py --url https://api.example.com --login-url https://api.example.com/auth/login --username john@example.com --password secret123

# Two-user BOLA testing (detects cross-user data access)
python main.py --url https://api.example.com --token1 "Bearer eyJ..." --token2 "Bearer eyJ..."

# Auto-login for both users
python main.py --url https://api.example.com \
  --login-url https://api.example.com/auth/login --username user1@example.com --password pass1 \
  --login-url2 https://api.example.com/auth/login --username2 user2@example.com --password2 pass2

# Output as JSON instead of HTML (useful for CI/CD pipelines)
python main.py --url https://api.example.com --token1 "Bearer eyJ..." --format json --output results.json

# Filter by minimum severity
python main.py --url https://api.example.com --token1 "Bearer eyJ..." --min-severity high

# Skip specific tests
python main.py --url https://api.example.com --token1 "Bearer eyJ..." --skip rate graphql
```

## Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `--url` | Yes | Base API URL |
| `--token1` | No* | JWT token for user 1 (`Bearer eyJ...`) |
| `--token2` | No | JWT token for user 2 (enables cross-user BOLA checks) |
| `--login-url` | No* | Login endpoint to auto-fetch token1 |
| `--username` | No* | Username/email for auto-login (token1) |
| `--password` | No* | Password for auto-login (token1) |
| `--login-url2` | No | Login endpoint to auto-fetch token2 |
| `--username2` | No | Username/email for auto-login (token2) |
| `--password2` | No | Password for auto-login (token2) |
| `--swagger` | No | Path to a Swagger/OpenAPI v2 or v3 file |
| `--output` | No | Output file path (default: `report.html`) |
| `--format` | No | Output format: `html` or `json` (default: `html`) |
| `--min-severity` | No | Minimum severity to include: `low` `medium` `high` `critical` (default: `low`) |
| `--skip` | No | Tests to skip: `bola auth mass rate exposure graphql` |

*Either `--token1` or (`--login-url` + `--username` + `--password`) is required.

## Example Output

```
[*] Target: https://api.example.com
[*] Logging in via https://api.example.com/auth/login ...
[*] Token1 acquired: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6...
[*] Loaded 24 endpoints

[*] BOLA/IDOR: 3 issue(s) found
[*] Auth Bypass: 2 issue(s) found
[*] Mass Assignment: 1 issue(s) found
[*] Rate Limiting: 1 issue(s) found
[*] Data Exposure: 0 issue(s) found
[*] GraphQL: 2 issue(s) found

[+] Total findings: 9
[!] 5 HIGH/CRITICAL issue(s) found — exiting with code 1
[+] Report saved → report.html
```

> The HTML report looks like this — each finding includes severity, description, request/response details, and remediation advice.

![APIStrike Report](https://i.imgur.com/placeholder.png)

---

## CI/CD Integration

APIStrike exits with code `1` if any HIGH or CRITICAL findings are detected, making it easy to fail pipelines on serious issues.

```yaml
# Example GitHub Actions step
- name: Run API Security Tests
  run: python main.py --url ${{ secrets.API_URL }} --token1 ${{ secrets.API_TOKEN }} --min-severity high
```

## Project Structure

```
api-security-tester/
├── main.py              # Entry point
├── config.py            # Shared constants and patterns
├── auth/
│   └── handler.py       # JWT manipulation (alg:none, expired, admin escalation)
├── parser/
│   ├── swagger.py       # OpenAPI v2/v3 parser
│   └── crawler.py       # Browser + regex + path-probe endpoint discovery
├── tests/
│   ├── bola.py          # BOLA/IDOR tests
│   ├── auth_bypass.py   # Auth bypass tests
│   ├── mass_assign.py   # Mass assignment tests
│   ├── rate_limit.py    # Rate limit tests
│   ├── data_exposure.py # Sensitive data exposure tests
│   └── graphql.py       # GraphQL-specific tests
└── reporter/
    └── report.py        # HTML/JSON report generator
```

## Output

An HTML report with severity-rated findings, plain-English explanations, clickable test URLs, and raw request/response details for developers. JSON output is also supported for programmatic consumption.
