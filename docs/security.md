# Application security

PhishGuard handles hostile input by design. This document lists the threats considered, the controls in place and what remains out of scope. It describes the **local** application only.

## Threat model

| Threat | Control | Tests |
|---|---|---|
| **SSRF** (the server being made to contact internal or attacker hosts) | Submitted URLs are never fetched, resolved or expanded. The only outbound requests go to the fixed endpoints of configured reputation providers. | `test_scanning_makes_no_outbound_requests` |
| **Stored / reflected XSS** via URLs, query names, search terms or rejected input | Jinja2 autoescaping everywhere (no `|safe`); client JS writes text with `textContent` only; CSP `script-src 'self'`, no inline scripts or styles, `object-src 'none'`, `base-uri 'none'` | `test_security.py` XSS tests |
| **CSRF** | Flask-WTF `CSRFProtect` on every POST/DELETE, including the JSON API (`X-CSRFToken`), because API identity is cookie-based; tokens are bound to the session | CSRF tests in `test_security.py` |
| **Cross-user data access** | Records carry `owner_hash`; every query in `services/history_service.py` filters on owner and expiry; another browser's IDs return 404 (indistinguishable from missing) | `test_other_sessions_cannot_read_or_delete_records` |
| **SQL injection** | SQLAlchemy expressions with bound parameters only; search uses `contains(..., autoescape=True)`; scan IDs validated as UUIDv4 | injection-style ID test |
| **Secret leakage** | Keys only from environment; never sent to the browser or returned by `/api/v1/status`; sent to Google in headers, not URLs; provider response bodies not logged | `test_status_reports_components_without_secrets`, provider tests |
| **Sensitive data in logs** | URLs are never logged (only scan ID and verdict); a filter strips query strings from request log lines; `ParsedURL.__repr__` hides the raw URL, path, query and fragment | logging tests |
| **Sensitive data at rest** | Full URLs not stored by default; passwords discarded at parse time; query values removed from `display_url`; keyed fingerprints; automatic expiry | `test_record_is_privacy_conscious_by_default` |
| **Unsafe deserialisation** | Only local joblib models whose SHA-256 matches their metadata and whose feature set matches the code are loaded | `test_tampered_model_is_refused` |
| **Denial of service** | Max URL length (`MAX_URL_LENGTH`), request body limit (16 KB), rate limits (scan endpoints and a global default), provider timeouts and cool-downs, pagination capped at 100 | rate-limit, oversized-input tests |
| **Information disclosure in errors** | Generic error pages / JSON; stack traces only in the server log; `Server` header removed | `test_unexpected_errors_do_not_leak_details` |
| **Clickjacking, MIME sniffing, referrer leakage** | `frame-ancestors 'none'`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` | header tests |
| **Parser confusion** | Browser-equivalent parsing of `@`, backslashes, encoded hosts, numeric IPs, IDN | `test_url_parser.py` |

## Sessions and cookies

* Cookie `phishguard_session`: signed, `HttpOnly`, `SameSite=Lax`, 30-day lifetime.
* `SESSION_COOKIE_SECURE` defaults to `false` because the local server uses plain HTTP; set it to `true` if you ever serve over HTTPS.
* `SECRET_KEY` comes from the environment; if absent, a random key is generated once into `instance/secret_key` (git-ignored). Changing the key invalidates sessions and makes existing history unreachable (records still expire normally).

## Rate limits

| Scope | Default | Setting |
|---|---|---|
| `POST /scan`, `POST /api/v1/scan` | 20/minute and 300/day per client IP | `SCAN_RATE_LIMIT` |
| Demo data loading | 5/minute | fixed |
| Everything else | 200/minute and 5,000/hour | `RATELIMIT_DEFAULT` |
| `GET /api/v1/health` | exempt | |

Limits use in-memory storage (reset on restart) and the socket's remote address. `X-Forwarded-For` is ignored on purpose.

## Security checks

* `ruff check .` with the flake8-bandit (`S`) rule set enabled.
* `bandit -c pyproject.toml -r phishguard config.py app.py scripts`
* `pip-audit -r requirements.txt`

See the README for the results of the last verification run and which of these could be executed.

## Residual risks and limitations

* Anonymous history is tied to a cookie. Anyone with access to the same browser profile can see that history; there are no user accounts.
* The in-memory rate limiter and cache are per-process.
* The development server (`flask run`) is not hardened; PhishGuard binds to `127.0.0.1` for that reason.
* Detection is heuristic. A *No threat detected* verdict is never a guarantee of safety.
* Model files are trusted after a hash check; the hash lives next to the model, so the check guards against corruption and accidental replacement, not against someone who can write to `ml_artifacts/`.
