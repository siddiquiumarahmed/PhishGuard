"""Google Safe Browsing (Lookup API v4) and Google Web Risk adapters.

Usage terms
-----------
* **Safe Browsing API** is intended for non-commercial use. Commercial use
  requires the **Web Risk API** (billing-enabled Google Cloud project).
  Check eligibility and terms before enabling either.

API keys are sent in the ``X-Goog-Api-Key`` header rather than the query
string so they do not appear in URLs, proxies or access logs. Response bodies
are never logged or echoed.
"""

from __future__ import annotations

from typing import Any

import requests

from phishguard import __version__
from phishguard.intelligence.base import (
    DEFAULT_TIMEOUT,
    LookupStatus,
    ProviderError,
    ProviderResult,
    ReputationProvider,
)

SAFE_BROWSING_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
WEB_RISK_ENDPOINT = "https://webrisk.googleapis.com/v1/uris:search"

SAFE_BROWSING_THREAT_TYPES = [
    "MALWARE",
    "SOCIAL_ENGINEERING",
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION",
]
WEB_RISK_THREAT_TYPES = ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"]


def _json(response: requests.Response) -> dict[str, Any]:
    data = response.json()
    if not isinstance(data, dict):
        raise ValueError("expected a JSON object")
    return data


class GoogleSafeBrowsingProvider(ReputationProvider):
    provider_id = "google_safe_browsing"
    display_name = "Google Safe Browsing"

    def __init__(
        self,
        api_key: str | None,
        timeout: tuple[float, float] = DEFAULT_TIMEOUT,
        session: requests.Session | None = None,
        client_id: str = "phishguard-local",
    ) -> None:
        super().__init__(timeout, session)
        self.api_key = (api_key or "").strip()
        self.client_id = client_id

    def is_configured(self) -> bool:
        return bool(self.api_key)

    def _query(self, url: str) -> ProviderResult:
        body = {
            "client": {"clientId": self.client_id, "clientVersion": __version__},
            "threatInfo": {
                "threatTypes": SAFE_BROWSING_THREAT_TYPES,
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }
        response = self.session.post(
            SAFE_BROWSING_ENDPOINT,
            json=body,
            timeout=self.timeout,
            headers={"X-Goog-Api-Key": self.api_key, "Content-Type": "application/json"},
        )
        if response.status_code == 400:
            raise ProviderError(
                LookupStatus.ERROR,
                "The service rejected the request (HTTP 400). Check that the API key is valid for Safe Browsing.",
            )
        self._status_from_http(response)
        data = _json(response)
        matches = data.get("matches", [])
        if not isinstance(matches, list):
            raise ValueError("'matches' must be a list")
        if not matches:
            return self._result(LookupStatus.NO_MATCH, "Not found on Safe Browsing lists.")
        types = sorted({str(m["threatType"]) for m in matches if isinstance(m, dict)})
        if not types:
            raise ValueError("matches without threatType")
        return self._result(LookupStatus.MATCH, "Listed by Google Safe Browsing.", types)


class GoogleWebRiskProvider(ReputationProvider):
    provider_id = "google_web_risk"
    display_name = "Google Web Risk"

    def __init__(
        self,
        api_key: str | None,
        timeout: tuple[float, float] = DEFAULT_TIMEOUT,
        session: requests.Session | None = None,
    ) -> None:
        super().__init__(timeout, session)
        self.api_key = (api_key or "").strip()

    def is_configured(self) -> bool:
        return bool(self.api_key)

    def _query(self, url: str) -> ProviderResult:
        params: list[tuple[str, str]] = [("uri", url)] + [("threatTypes", t) for t in WEB_RISK_THREAT_TYPES]
        response = self.session.get(
            WEB_RISK_ENDPOINT,
            params=params,
            timeout=self.timeout,
            headers={"X-Goog-Api-Key": self.api_key},
        )
        if response.status_code == 400:
            raise ProviderError(LookupStatus.ERROR, "The service rejected the request (HTTP 400).")
        self._status_from_http(response)
        data = _json(response)
        threat = data.get("threat")
        if threat is None:
            return self._result(LookupStatus.NO_MATCH, "Not found on Web Risk lists.")
        if not isinstance(threat, dict) or not isinstance(threat.get("threatTypes"), list):
            raise ValueError("malformed 'threat' object")
        types = sorted(str(t) for t in threat["threatTypes"])
        if not types:
            raise ValueError("empty threatTypes")
        return self._result(LookupStatus.MATCH, "Listed by Google Web Risk.", types)
