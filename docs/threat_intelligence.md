# Threat intelligence

External reputation services are **optional**. Without credentials PhishGuard still analyses every URL with its rules and says clearly that no blocklist was checked.

## Provider contract

Every provider subclasses `ReputationProvider` (`phishguard/intelligence/base.py`) and implements two methods:

```python
class MyProvider(ReputationProvider):
    provider_id = "my_provider"
    display_name = "My Provider"

    def is_configured(self) -> bool: ...
    def _query(self, url: str) -> ProviderResult: ...   # may raise ProviderError or requests exceptions
```

`lookup()` wraps `_query()` and guarantees a `ProviderResult` is always returned:

| Status | Meaning | Counts as a completed check? |
|---|---|---|
| `match` | Verified listing (authoritative) | yes |
| `unverified_listing` | Reported but not verified (PhishTank) | yes, raises the verdict to at least *Suspicious* |
| `no_match` | Not on the provider's lists | yes, never lowers a verdict |
| `not_configured` | No credentials; no request made | no (not a failure) |
| `timeout`, `quota_exceeded`, `auth_error`, `malformed_response`, `error` | Lookup failed | no, **never treated as clean** |

After a quota or credential error the provider is skipped for two minutes (cool-down) rather than hammered on every scan.

To add a provider, implement the class and add it to `build_providers()` in `intelligence/service.py`. Nothing else changes.

## Supported providers

### Google Safe Browsing (Lookup API v4)

* Setting: `GOOGLE_SAFE_BROWSING_API_KEY`
* Endpoint: `POST https://safebrowsing.googleapis.com/v4/threatMatches:find`
* Threat types: `MALWARE`, `SOCIAL_ENGINEERING`, `UNWANTED_SOFTWARE`, `POTENTIALLY_HARMFUL_APPLICATION`
* Terms: Google states the Safe Browsing API is for **non-commercial** use; commercial use should use Web Risk. Create a key in a Google Cloud project with the Safe Browsing API enabled and restrict it to that API.
* Google also publishes a v5 API; the adapter design allows a v5 provider to be added alongside.

### Google Web Risk

* Setting: `GOOGLE_WEB_RISK_API_KEY`
* Endpoint: `GET https://webrisk.googleapis.com/v1/uris:search`
* Requires a billing-enabled Google Cloud project; intended for commercial use. Check pricing before enabling.

### PhishTank

* Settings: `PHISHTANK_ENABLED=true`, optional `PHISHTANK_API_KEY`, `PHISHTANK_USERNAME`
* Endpoint: `POST https://checkurl.phishtank.com/checkurl/` (`format=json`)
* PhishTank asks for a descriptive `User-Agent` (`phishtank/<username>`); the app key is optional but raises the rate limit. HTTP 509 indicates the limit was exceeded.
* Interpretation: verified **and** still valid → `match`; reported but unverified → `unverified_listing`; verified but no longer valid → `no_match`.

## Privacy

When a provider is configured, the **normalised URL** (scheme, host, port, path and query; never credentials or fragment) is sent to it. API keys travel in request headers (`X-Goog-Api-Key`) rather than URLs, are never sent to the browser, never logged and never echoed in error messages; response bodies are not logged. The privacy page in the app states which services are active.

## Caching and timeouts

* Connect/read timeouts: `INTEL_CONNECT_TIMEOUT` (3.05 s) / `INTEL_READ_TIMEOUT` (6 s).
* Providers are queried in parallel.
* Completed results are cached in memory for `INTEL_CACHE_TTL_SECONDS` (default 30 minutes, up to 2,048 entries). Cache keys are SHA-256 digests of provider + URL. Failures are not cached. The cache is cleared on restart.

## Testing

`tests/test_reputation.py` replaces the HTTP session with a fake, so no request leaves the machine. It covers missing credentials, matches, non-matches, HTTP 400/401/403/429/500/509, timeouts, connection errors, invalid JSON, unexpected JSON shapes, the cool-down, caching of successes only and key redaction.
