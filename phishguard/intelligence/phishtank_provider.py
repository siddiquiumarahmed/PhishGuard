"""PhishTank ``checkurl`` adapter.

PhishTank (operated by Cisco Talos) lets anyone query its community-verified
phishing database. An application key is optional but strongly raises rate
limits; a descriptive User-Agent (``phishtank/<username>``) is required by
the service. Review PhishTank's terms of use before enabling it.

Interpretation
--------------
* in database + verified + still valid  -> ``MATCH`` (authoritative)
* in database + not yet verified        -> ``UNVERIFIED_LISTING`` (warning only)
* in database + verified + not valid    -> ``NO_MATCH`` (was reported, no longer active)
* not in database                       -> ``NO_MATCH``
"""

from __future__ import annotations

from typing import Any

import requests

from phishguard.intelligence.base import (
    DEFAULT_TIMEOUT,
    LookupStatus,
    ProviderError,
    ProviderResult,
    ReputationProvider,
)

PHISHTANK_ENDPOINT = "https://checkurl.phishtank.com/checkurl/"


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"y", "yes", "true", "1"}
    if isinstance(value, int):
        return value == 1
    return False


class PhishTankProvider(ReputationProvider):
    provider_id = "phishtank"
    display_name = "PhishTank"

    def __init__(
        self,
        enabled: bool,
        app_key: str | None = None,
        username: str | None = None,
        timeout: tuple[float, float] = DEFAULT_TIMEOUT,
        session: requests.Session | None = None,
    ) -> None:
        super().__init__(timeout, session)
        self.enabled = enabled
        self.app_key = (app_key or "").strip()
        self.username = (username or "").strip() or "phishguard-local"

    def is_configured(self) -> bool:
        return self.enabled

    def _query(self, url: str) -> ProviderResult:
        data = {"url": url, "format": "json"}
        if self.app_key:
            data["app_key"] = self.app_key
        response = self.session.post(
            PHISHTANK_ENDPOINT,
            data=data,
            timeout=self.timeout,
            headers={"User-Agent": f"phishtank/{self.username}"},
        )
        self._status_from_http(response)
        payload = response.json()
        if not isinstance(payload, dict):
            raise ValueError("expected a JSON object")
        if payload.get("errortext"):
            raise ProviderError(LookupStatus.ERROR, "PhishTank reported an error for this request.")
        results = payload["results"]
        if not isinstance(results, dict) or "in_database" not in results:
            raise ValueError("missing results.in_database")

        if not _truthy(results.get("in_database")):
            return self._result(LookupStatus.NO_MATCH, "Not in the PhishTank database.")
        verified = _truthy(results.get("verified"))
        valid = _truthy(results.get("valid"))
        if verified and valid:
            return self._result(LookupStatus.MATCH, "Verified phishing site in PhishTank.", ["PHISHING"])
        if not verified:
            return self._result(
                LookupStatus.UNVERIFIED_LISTING,
                "Reported to PhishTank but not yet verified by the community.",
                ["PHISHING"],
            )
        return self._result(
            LookupStatus.NO_MATCH, "Previously reported to PhishTank; no longer listed as an active phish."
        )
