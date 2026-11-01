# REST API (v1)

Base path: `/api/v1`. All responses are JSON:

```json
{"ok": true,  "data": {}, "meta": {}}
{"ok": false, "error": {"code": "invalid_url.missing_scheme", "message": "…", "field": "url"}}
```

## Authentication and CSRF

The API uses the same anonymous, cookie-based session as the web UI, so each client only sees its own scans. Because identity is carried by a cookie, state-changing requests must include a CSRF token:

1. `GET /api/v1/session` → `{"data": {"csrf_token": "…", "csrf_header": "X-CSRFToken"}}` and a session cookie.
2. Send the cookie and `X-CSRFToken: <token>` with every `POST` / `DELETE`.

## Endpoints

### `POST /api/v1/scan`

Body: `{"url": "https://…"}`. Content type must be `application/json`. No other fields are accepted. Rate limited by `SCAN_RATE_LIMIT`.

`201 Created`, `Location: /api/v1/scans/<id>`:

```json
{
  "ok": true,
  "data": {
    "id": "8f0c2a4e-…",
    "created_at": "2026-10-20T15:07:12Z",
    "expires_at": "2026-10-27T15:07:12Z",
    "display_url": "https://paypal.com.account-verify.example.net/signin?token=…",
    "host": "paypal.com.account-verify.example.net",
    "verdict": "high_risk",
    "label": "High risk",
    "summary": "Strong indicators of deception were found in this address.",
    "reasons": ["Official PayPal domain placed in front of another domain (critical)", "…"],
    "heuristic_index": 80,
    "index_band": "high",
    "decisive_methods": ["rules"],
    "findings": [{"rule_id": "PG-BRAND-001", "title": "…", "severity": "critical",
                  "explanation": "…", "evidence": ["…"], "recommendation": "…", "category": "brand"}],
    "threat_intelligence": [{"provider": "google_safe_browsing", "status": "not_configured",
                             "status_label": "Not configured — not checked", "threat_types": [], "…": "…"}],
    "machine_learning": {"status": "unavailable", "score": null, "detail": "no trained model found", "…": "…"},
    "components": {"rules": {"status": "ok"}, "reputation": {"status": "not_configured"}, "ml": {"status": "unavailable"}},
    "limitations": ["No threat-intelligence service is configured, …"],
    "recommendations": ["Do not open this link or enter any information on the page.", "…"],
    "anatomy": {"scheme": "https", "subdomain": "paypal.com.account-verify", "registered": "example.net", "…": "…"},
    "detector_version": "detector-1.0.0",
    "model_version": null,
    "links": {"self": "/api/v1/scans/8f0c…", "report": "/scans/8f0c…"}
  }
}
```

`verdict` is one of `confirmed_malicious`, `high_risk`, `suspicious`, `no_threat_detected`, `inconclusive`.

### `GET /api/v1/scans`

Query parameters: `q` (search host/address, ≤ 100 chars), `verdict`, `page` (≥ 1), `per_page` (1–100, default 20). Returns summaries and `meta` with `page`, `per_page`, `total`, `pages`, `has_next`, `has_prev`.

### `GET /api/v1/scans/<id>`

Full report for one of your scans. Unknown, expired or other sessions' IDs all return `404 not_found`.

### `DELETE /api/v1/scans/<id>`

Deletes one of your scans. Requires `X-CSRFToken`.

### `GET /api/v1/health`

`{"status": "ok", "database": "ok"}`, or HTTP 503 with `"database": "unavailable"`. Not rate limited.

### `GET /api/v1/status`

Component availability: application and detector versions, rule count, each provider's `configured` flag, ML status and model version, retention days, whether normalised URLs are stored, and `"fetches_submitted_urls": false`. Never returns keys.

## Error codes

| HTTP | `error.code` | Cause |
|---|---|---|
| 400 | `csrf_failed` | Missing or invalid CSRF token |
| 400 | `invalid_json`, `invalid_body`, `missing_field`, `invalid_type`, `invalid_parameter` | Malformed request |
| 404 | `not_found` | Unknown route or scan |
| 405 | `method_not_allowed` | Wrong HTTP method |
| 413 | `payload_too_large` | Body over 16 KB |
| 415 | `unsupported_media_type` | Body is not JSON |
| 422 | `invalid_url.<reason>` | URL rejected by validation (`missing_scheme`, `unsupported_scheme`, `too_long`, `invalid_ip`, `invalid_hostname`, …) |
| 429 | `rate_limited` | Rate limit reached |
| 500 | `internal_error` | Unexpected error; details only in the server log |

## Examples

PowerShell:

```powershell
$base = "http://127.0.0.1:5000/api/v1"
$s = Invoke-RestMethod "$base/session" -SessionVariable pg
$body = @{ url = "http://paypal.com@203.0.113.7/login" } | ConvertTo-Json
$r = Invoke-RestMethod "$base/scan" -Method Post -WebSession $pg -ContentType "application/json" `
       -Headers @{ "X-CSRFToken" = $s.data.csrf_token } -Body $body
$r.data.verdict
Invoke-RestMethod "$base/scans?verdict=high_risk" -WebSession $pg
```

Python:

```python
import requests

s = requests.Session()
base = "http://127.0.0.1:5000/api/v1"
token = s.get(f"{base}/session").json()["data"]["csrf_token"]
r = s.post(f"{base}/scan", json={"url": "https://xn--pypal-4ve.example/login"}, headers={"X-CSRFToken": token})
print(r.status_code, r.json()["data"]["verdict"])
```
