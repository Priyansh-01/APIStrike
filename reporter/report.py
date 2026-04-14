from datetime import datetime

SEVERITY_COLOR = {
    "CRITICAL": "#c0392b",
    "HIGH":     "#e67e22",
    "MEDIUM":   "#d4ac0d",
    "LOW":      "#27ae60",
}

SEVERITY_BG = {
    "CRITICAL": "#2c0b0b",
    "HIGH":     "#2c1a0b",
    "MEDIUM":   "#2c250b",
    "LOW":      "#0b2c14",
}

# Plain-English explanation for each finding type
PLAIN_ENGLISH = {
    "BOLA/IDOR": (
        "One user can access another user's private data.",
        "The system does not check whether the logged-in user actually owns the resource they are requesting. "
        "By changing a number in the URL (e.g. /users/1 → /users/2), an attacker can read or modify someone else's account, orders, or files.",
        "Change the ID in the URL to a different number and see if you get someone else's data back."
    ),
    "BOLA/IDOR (ID Enumeration)": (
        "Guessing IDs exposes other users' data.",
        "The API uses simple sequential numbers as IDs (1, 2, 3…). An attacker can loop through numbers to harvest data from every account on the system.",
        "Try incrementing or decrementing the ID in the URL and check if different users' data is returned."
    ),
    "Auth Bypass": (
        "The page or data is accessible without logging in.",
        "This endpoint returned data even when no login token was provided, or when a fake/expired token was used. "
        "Sensitive pages should always require a valid login.",
        "Open the URL in a browser without logging in, or remove the Authorization header and repeat the request."
    ),
    "Mass Assignment": (
        "The API accepts fields it should ignore.",
        "When sending data to the server, extra fields like 'role', 'isAdmin', or 'balance' were accepted and reflected back. "
        "An attacker could send {\"isAdmin\": true} to escalate their own privileges.",
        "Send a POST/PUT request with extra fields like 'role' or 'isAdmin' and check if they appear in the response."
    ),
    "Missing Rate Limiting": (
        "No limit on how many times you can try.",
        "This login or verification endpoint accepted 100+ requests in a row with no slowdown or block. "
        "An attacker can use this to brute-force passwords or OTP codes automatically.",
        "Send the same request 100+ times rapidly and check if any are blocked or slowed down."
    ),
    "Sensitive Data Exposure": (
        "Private information is visible in the response.",
        "The API response contains sensitive data such as email addresses, passwords, API keys, or tokens "
        "that should not be returned to the caller.",
        "Call the endpoint and inspect the full response body for emails, passwords, tokens, or keys."
    ),
    "GraphQL Introspection Enabled": (
        "The API's full structure is publicly visible.",
        "GraphQL introspection lets anyone query the complete map of the API — every operation, field, and data type. "
        "This gives attackers a blueprint to find hidden or sensitive operations.",
        "Send the introspection query to the GraphQL endpoint and check if the full schema is returned."
    ),
    "GraphQL Batching Attack": (
        "Multiple requests can be sent as one to bypass limits.",
        "The GraphQL endpoint accepts arrays of queries in a single request. "
        "This can be used to bypass rate limiting on login or OTP endpoints by sending 100 attempts in one HTTP call.",
        "Send an array of login mutations in one POST request and check if all are processed."
    ),
    "GraphQL Auth Bypass": (
        "GraphQL data is accessible without logging in.",
        "The GraphQL endpoint returned data without any authentication token. "
        "All GraphQL queries should require a valid login.",
        "Send a GraphQL query with no Authorization header and check if data is returned."
    ),
    "GraphQL Field Suggestion Enabled": (
        "The API hints at hidden field names.",
        "When a wrong field name is typed, the server responds with 'Did you mean X?' — leaking valid field names "
        "even when introspection is disabled. Attackers use this to map the schema manually.",
        "Send a GraphQL query with a slightly misspelled field name and check if the server suggests the correct one."
    ),
    "GraphQL Potential IDOR": (
        "A GraphQL query accepts an ID — may allow accessing other users' data.",
        "This query takes an 'id' argument. If the server does not verify ownership, "
        "an attacker can change the ID to access another user's data through GraphQL.",
        "Call the query with different ID values and check if other users' data is returned."
    ),
}

VALIDATED_TYPES = {"BOLA/IDOR", "BOLA/IDOR (ID Enumeration)", "Mass Assignment", "Sensitive Data Exposure",
                   "GraphQL Introspection Enabled", "GraphQL Auth Bypass", "GraphQL Batching Attack",
                   "GraphQL Field Suggestion Enabled"}


def _extract_manual_url(finding: dict, base_url: str) -> str:
    """Build a clickable manual test URL from the finding."""
    ep = finding.get("endpoint", "")
    req = finding.get("request", "")
    # Try to get the full URL from request field first
    for line in req.splitlines():
        line = line.strip()
        if line.startswith("http"):
            return line.split(" ")[0] if " " in line else line
        if line.startswith("GET ") or line.startswith("POST ") or line.startswith("PUT ") or line.startswith("DELETE "):
            parts = line.split(" ")
            if len(parts) >= 2:
                path = parts[1]
                if path.startswith("http"):
                    return path
                return base_url.rstrip("/") + path
    # Fallback: extract path from endpoint field
    parts = ep.split(" ", 1)
    if len(parts) == 2:
        path = parts[1]
        if path.startswith("http"):
            return path
        return base_url.rstrip("/") + path
    return ""


def generate_report(findings: list[dict], output_path: str, target: str):
    total = len(findings)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        sev = f.get("severity", "LOW")
        counts[sev] = counts.get(sev, 0) + 1

    # Deduplicate by (type, endpoint) — keep first occurrence
    seen_keys = set()
    unique_findings = []
    for f in findings:
        key = (f.get("type"), f.get("endpoint"))
        if key not in seen_keys:
            seen_keys.add(key)
            unique_findings.append(f)

    cards = ""
    for i, f in enumerate(unique_findings):
        sev = f.get("severity", "LOW")
        ftype = f.get("type", "Unknown")
        color = SEVERITY_COLOR.get(sev, "#ccc")
        bg = SEVERITY_BG.get(sev, "#1a1a1a")

        plain = PLAIN_ENGLISH.get(ftype, (
            ftype,
            f.get("detail", ""),
            "Review the endpoint manually."
        ))
        short_desc, long_desc, how_to_test = plain

        is_validated = ftype in VALIDATED_TYPES
        validated_badge = (
            '<span class="val-badge confirmed">✅ Confirmed</span>'
            if is_validated else
            '<span class="val-badge manual">🔍 Needs Manual Check</span>'
        )

        manual_url = _extract_manual_url(f, target)
        url_link = f'<a href="{manual_url}" target="_blank" class="test-url">{manual_url}</a>' if manual_url else "N/A"

        req_headers = ""
        if f.get("request_headers"):
            req_headers = "\n".join(f"{k}: {v}" for k, v in f["request_headers"].items())

        cards += f"""
<div class="card" id="finding-{i+1}" style="border-left: 5px solid {color}; background: {bg};">
  <div class="card-top">
    <div class="card-left">
      <span class="sev-badge" style="background:{color}">{sev}</span>
      {validated_badge}
      <span class="finding-num">#{i+1}</span>
    </div>
    <div class="card-title">{ftype}</div>
  </div>

  <div class="card-body">
    <div class="plain-summary">💬 <strong>In plain English:</strong> {short_desc}</div>

    <div class="section-label">What happened</div>
    <div class="section-text">{long_desc}</div>

    <div class="section-label">Affected endpoint</div>
    <div class="section-text endpoint-text">{_escape(f.get('endpoint', 'N/A'))}</div>

    <div class="section-label">Technical detail</div>
    <div class="section-text">{_escape(f.get('detail', 'N/A'))}</div>

    <div class="section-label">How to test manually</div>
    <div class="section-text">{how_to_test}<br><br>🔗 URL: {url_link}</div>

    <details class="tech-details">
      <summary>🔧 Technical details (for developers)</summary>
      <div class="tech-inner">
        <div class="tech-label">HTTP Status Code</div>
        <pre>{f.get('status_code', 'N/A')}</pre>
        <div class="tech-label">Request sent</div>
        <pre>{_escape(f.get('request', 'N/A'))}\n{_escape(req_headers)}</pre>
        <div class="tech-label">Response preview</div>
        <pre>{_escape(f.get('response_body', 'N/A'))}</pre>
      </div>
    </details>
  </div>
</div>"""

    # Summary table
    summary_rows = ""
    for i, f in enumerate(unique_findings):
        sev = f.get("severity", "LOW")
        color = SEVERITY_COLOR.get(sev, "#ccc")
        ftype = f.get("type", "")
        ep = _escape(f.get("endpoint", ""))
        plain_short = PLAIN_ENGLISH.get(ftype, (ftype,))[0]
        is_validated = ftype in VALIDATED_TYPES
        val = "✅ Confirmed" if is_validated else "🔍 Manual"
        summary_rows += f"""
        <tr>
          <td><a href="#finding-{i+1}" class="ref-link">#{i+1}</a></td>
          <td><span class="sev-badge" style="background:{color}">{sev}</span></td>
          <td>{ftype}</td>
          <td class="ep-cell">{ep}</td>
          <td>{plain_short}</td>
          <td>{val}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Report — {_escape(target)}</title>
<style>
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
          background: #0f1117; color: #d4d8e1; line-height: 1.6; padding: 0; }}

  .header {{ background: linear-gradient(135deg, #1a1f2e 0%, #0f1117 100%);
             border-bottom: 1px solid #2a2f3e; padding: 32px 40px; }}
  .header h1 {{ font-size: 26px; color: #fff; margin-bottom: 6px; }}
  .header .meta {{ color: #7a8299; font-size: 14px; }}
  .header .meta span {{ color: #a0a8c0; }}

  .content {{ max-width: 1100px; margin: 0 auto; padding: 32px 24px; }}

  /* Score bar */
  .score-bar {{ display: flex; gap: 16px; margin-bottom: 36px; flex-wrap: wrap; }}
  .score-box {{ flex: 1; min-width: 120px; background: #1a1f2e; border-radius: 10px;
                padding: 18px 20px; text-align: center; border: 1px solid #2a2f3e; }}
  .score-box .num {{ font-size: 36px; font-weight: 700; display: block; }}
  .score-box .label {{ font-size: 12px; color: #7a8299; text-transform: uppercase;
                       letter-spacing: 1px; margin-top: 4px; }}
  .score-box.total {{ border-color: #3a4060; }}
  .score-box.total .num {{ color: #fff; }}

  /* Summary table */
  .section-title {{ font-size: 16px; font-weight: 600; color: #fff; margin-bottom: 14px;
                    padding-bottom: 8px; border-bottom: 1px solid #2a2f3e; }}
  .summary-table {{ width: 100%; border-collapse: collapse; margin-bottom: 40px;
                    background: #1a1f2e; border-radius: 10px; overflow: hidden;
                    border: 1px solid #2a2f3e; font-size: 13px; }}
  .summary-table th {{ background: #12161f; color: #7a8299; text-transform: uppercase;
                       font-size: 11px; letter-spacing: 0.8px; padding: 12px 14px;
                       text-align: left; border-bottom: 1px solid #2a2f3e; }}
  .summary-table td {{ padding: 11px 14px; border-bottom: 1px solid #1f2535; vertical-align: middle; }}
  .summary-table tr:last-child td {{ border-bottom: none; }}
  .summary-table tr:hover td {{ background: #1f2535; }}
  .ep-cell {{ font-family: monospace; font-size: 12px; color: #79c0ff; }}
  .ref-link {{ color: #58a6ff; text-decoration: none; font-weight: 600; }}
  .ref-link:hover {{ text-decoration: underline; }}

  /* Cards */
  .card {{ border-radius: 10px; margin-bottom: 20px; overflow: hidden; }}
  .card-top {{ display: flex; align-items: center; gap: 12px; padding: 14px 20px;
               background: rgba(255,255,255,0.03); border-bottom: 1px solid rgba(255,255,255,0.06); }}
  .card-left {{ display: flex; align-items: center; gap: 8px; flex-shrink: 0; }}
  .card-title {{ font-size: 16px; font-weight: 600; color: #fff; }}
  .finding-num {{ color: #4a5270; font-size: 13px; }}

  .sev-badge {{ padding: 3px 10px; border-radius: 20px; font-size: 11px;
                font-weight: 700; color: #000; letter-spacing: 0.5px; }}
  .val-badge {{ padding: 3px 10px; border-radius: 20px; font-size: 11px; font-weight: 600; }}
  .val-badge.confirmed {{ background: #0d3320; color: #2ecc71; border: 1px solid #1a6640; }}
  .val-badge.manual {{ background: #1a2040; color: #79c0ff; border: 1px solid #2a3060; }}

  .card-body {{ padding: 20px; }}
  .plain-summary {{ background: rgba(255,255,255,0.04); border-radius: 8px;
                    padding: 14px 16px; margin-bottom: 18px; font-size: 15px;
                    color: #e0e4f0; border-left: 3px solid #58a6ff; }}

  .section-label {{ font-size: 11px; text-transform: uppercase; letter-spacing: 1px;
                    color: #5a6280; font-weight: 600; margin-top: 16px; margin-bottom: 6px; }}
  .section-text {{ font-size: 14px; color: #b0b8d0; }}
  .endpoint-text {{ font-family: monospace; font-size: 13px; color: #79c0ff;
                    background: #0d1117; padding: 8px 12px; border-radius: 6px; }}

  .test-url {{ color: #58a6ff; word-break: break-all; }}
  .test-url:hover {{ color: #79c0ff; }}

  .tech-details {{ margin-top: 18px; }}
  .tech-details summary {{ cursor: pointer; color: #5a6280; font-size: 13px;
                            padding: 8px 0; user-select: none; }}
  .tech-details summary:hover {{ color: #79c0ff; }}
  .tech-inner {{ margin-top: 10px; }}
  .tech-label {{ font-size: 11px; text-transform: uppercase; letter-spacing: 1px;
                 color: #4a5270; margin-top: 12px; margin-bottom: 4px; }}
  pre {{ background: #0d1117; padding: 12px; border-radius: 6px; font-size: 12px;
         color: #7a8299; white-space: pre-wrap; word-break: break-all;
         border: 1px solid #1a1f2e; overflow-x: auto; }}

  .empty {{ text-align: center; padding: 60px; color: #4a5270; font-size: 16px; }}
  .disclaimer {{ background: #1a1f2e; border: 1px solid #2a2f3e; border-radius: 8px;
                 padding: 16px 20px; margin-bottom: 32px; font-size: 13px; color: #7a8299; }}
  .disclaimer strong {{ color: #a0a8c0; }}
</style>
</head>
<body>

<div class="header">
  <h1>🔐 API Security Test Report</h1>
  <div class="meta">
    Target: <span>{_escape(target)}</span> &nbsp;·&nbsp;
    Scanned: <span>{now}</span> &nbsp;·&nbsp;
    Unique Findings: <span>{len(unique_findings)}</span>
  </div>
</div>

<div class="content">

  <div class="score-bar">
    <div class="score-box total">
      <span class="num">{len(unique_findings)}</span>
      <span class="label">Total Issues</span>
    </div>
    <div class="score-box">
      <span class="num" style="color:{SEVERITY_COLOR['CRITICAL']}">{counts['CRITICAL']}</span>
      <span class="label">Critical</span>
    </div>
    <div class="score-box">
      <span class="num" style="color:{SEVERITY_COLOR['HIGH']}">{counts['HIGH']}</span>
      <span class="label">High</span>
    </div>
    <div class="score-box">
      <span class="num" style="color:{SEVERITY_COLOR['MEDIUM']}">{counts['MEDIUM']}</span>
      <span class="label">Medium</span>
    </div>
    <div class="score-box">
      <span class="num" style="color:{SEVERITY_COLOR['LOW']}">{counts['LOW']}</span>
      <span class="label">Low</span>
    </div>
  </div>

  <div class="disclaimer">
    <strong>Note:</strong> Findings marked <strong>✅ Confirmed</strong> were automatically validated by the tool
    (the vulnerability was proven by the response). Findings marked <strong>🔍 Needs Manual Check</strong>
    are suspicious and require a human to verify — the URL and steps are provided for each one.
  </div>

  {'<div class="section-title">📋 All Findings at a Glance</div><table class="summary-table"><thead><tr><th>#</th><th>Severity</th><th>Issue Type</th><th>Endpoint</th><th>Plain English</th><th>Status</th></tr></thead><tbody>' + summary_rows + '</tbody></table>' if unique_findings else ''}

  <div class="section-title">🔍 Detailed Findings</div>

  {cards if cards else '<div class="empty">✅ No issues found on this target.</div>'}

</div>
</body>
</html>"""

    with open(output_path, "w") as fh:
        fh.write(html)

    print(f"[+] Report saved → {output_path}")


def _escape(text: str) -> str:
    if not isinstance(text, str):
        text = str(text)
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
