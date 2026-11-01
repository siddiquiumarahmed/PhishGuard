"""Reputation service: runs all providers (in parallel), with caching.

Adding a provider means implementing :class:`ReputationProvider` and adding it
in :func:`build_providers`; nothing else in the application changes.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from typing import Any

from phishguard.intelligence.base import LookupStatus, ProviderResult, ReputationProvider
from phishguard.intelligence.cache import TTLCache, cache_key
from phishguard.intelligence.google_provider import GoogleSafeBrowsingProvider, GoogleWebRiskProvider
from phishguard.intelligence.phishtank_provider import PhishTankProvider


class ReputationService:
    def __init__(self, providers: Sequence[ReputationProvider], cache: TTLCache[ProviderResult] | None = None) -> None:
        self.providers = list(providers)
        self.cache: TTLCache[ProviderResult] = cache if cache is not None else TTLCache()

    def _check_one(self, provider: ReputationProvider, url: str) -> ProviderResult:
        key = cache_key(provider.provider_id, url)
        if provider.is_configured():
            hit = self.cache.get(key)
            if hit is not None:
                return replace(hit, cached=True)
        result = provider.lookup(url)
        if result.status.completed:
            self.cache.set(key, result)
        return result

    def check(self, url: str) -> list[ProviderResult]:
        if not self.providers:
            return []
        active = [p for p in self.providers if p.is_configured()]
        results: dict[str, ProviderResult] = {}
        for p in self.providers:
            if p not in active:
                results[p.provider_id] = p.lookup(url)  # returns NOT_CONFIGURED without I/O
        if active:
            with ThreadPoolExecutor(max_workers=len(active), thread_name_prefix="reputation") as pool:
                futures = {p.provider_id: pool.submit(self._check_one, p, url) for p in active}
                for pid, future in futures.items():
                    results[pid] = future.result()
        return [results[p.provider_id] for p in self.providers]

    def describe(self) -> list[dict[str, object]]:
        return [
            {"provider": p.provider_id, "display_name": p.display_name, "configured": p.is_configured()}
            for p in self.providers
        ]


def build_providers(config: Mapping[str, Any]) -> list[ReputationProvider]:
    timeout = (float(config.get("INTEL_CONNECT_TIMEOUT", 3.05)), float(config.get("INTEL_READ_TIMEOUT", 6.0)))
    return [
        GoogleSafeBrowsingProvider(config.get("GOOGLE_SAFE_BROWSING_API_KEY"), timeout=timeout),
        GoogleWebRiskProvider(config.get("GOOGLE_WEB_RISK_API_KEY"), timeout=timeout),
        PhishTankProvider(
            enabled=bool(config.get("PHISHTANK_ENABLED", False)),
            app_key=config.get("PHISHTANK_API_KEY"),
            username=config.get("PHISHTANK_USERNAME"),
            timeout=timeout,
        ),
    ]


def build_service(config: Mapping[str, Any]) -> ReputationService:
    cache: TTLCache[ProviderResult] = TTLCache(
        ttl_seconds=float(config.get("INTEL_CACHE_TTL_SECONDS", 1800)),
        max_entries=int(config.get("INTEL_CACHE_MAX_ENTRIES", 2048)),
    )
    return ReputationService(build_providers(config), cache)


__all__ = ["LookupStatus", "ReputationService", "build_providers", "build_service"]
