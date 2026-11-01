"""Provider-adapter contract for external URL reputation services.

Every provider returns a :class:`ProviderResult` and never raises. The status
distinguishes three things that must never be conflated:

* a completed lookup that found the URL (``MATCH`` / ``UNVERIFIED_LISTING``),
* a completed lookup that did not find it (``NO_MATCH``), and
* a lookup that did not happen or failed (``NOT_CONFIGURED`` and the error
  statuses). A failed lookup is **never** treated as a clean result.
"""

from __future__ import annotations

import logging
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum

import requests

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = (3.05, 6.0)  # (connect, read) seconds


class LookupStatus(StrEnum):
    MATCH = "match"
    UNVERIFIED_LISTING = "unverified_listing"
    NO_MATCH = "no_match"
    NOT_CONFIGURED = "not_configured"
    TIMEOUT = "timeout"
    QUOTA_EXCEEDED = "quota_exceeded"
    AUTH_ERROR = "auth_error"
    MALFORMED_RESPONSE = "malformed_response"
    ERROR = "error"

    @property
    def completed(self) -> bool:
        return self in (LookupStatus.MATCH, LookupStatus.UNVERIFIED_LISTING, LookupStatus.NO_MATCH)

    @property
    def failed(self) -> bool:
        return self in (
            LookupStatus.TIMEOUT,
            LookupStatus.QUOTA_EXCEEDED,
            LookupStatus.AUTH_ERROR,
            LookupStatus.MALFORMED_RESPONSE,
            LookupStatus.ERROR,
        )


STATUS_LABELS = {
    LookupStatus.MATCH: "Listed as malicious",
    LookupStatus.UNVERIFIED_LISTING: "Reported, not yet verified",
    LookupStatus.NO_MATCH: "Not listed",
    LookupStatus.NOT_CONFIGURED: "Not configured — not checked",
    LookupStatus.TIMEOUT: "Timed out — not checked",
    LookupStatus.QUOTA_EXCEEDED: "Quota exceeded — not checked",
    LookupStatus.AUTH_ERROR: "Credentials rejected — not checked",
    LookupStatus.MALFORMED_RESPONSE: "Unreadable response — not checked",
    LookupStatus.ERROR: "Service error — not checked",
}


@dataclass
class ProviderResult:
    provider: str
    display_name: str
    status: LookupStatus
    threat_types: list[str] = field(default_factory=list)
    detail: str = ""
    checked_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat(timespec="seconds"))
    cached: bool = False
    latency_ms: int | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "provider": self.provider,
            "display_name": self.display_name,
            "status": self.status.value,
            "status_label": STATUS_LABELS[self.status],
            "threat_types": list(self.threat_types),
            "detail": self.detail,
            "checked_at": self.checked_at,
            "cached": self.cached,
            "latency_ms": self.latency_ms,
        }


class ProviderError(Exception):
    """Raised inside a provider implementation to report a specific failure status."""

    def __init__(self, status: LookupStatus, detail: str) -> None:
        super().__init__(detail)
        self.status = status
        self.detail = detail


class ReputationProvider(ABC):
    """Base class. Subclasses implement :meth:`_query` and :meth:`is_configured`."""

    provider_id: str = "base"
    display_name: str = "Base provider"
    #: Seconds to stop calling a provider after quota/auth failures.
    cooldown_seconds: float = 120.0

    def __init__(self, timeout: tuple[float, float] = DEFAULT_TIMEOUT, session: requests.Session | None = None) -> None:
        self.timeout = timeout
        self.session = session or requests.Session()
        self._cooldown_until = 0.0
        self._cooldown_status: LookupStatus | None = None
        self._lock = threading.Lock()

    @abstractmethod
    def is_configured(self) -> bool:
        """True when the credentials/settings needed for a lookup are present."""

    @abstractmethod
    def _query(self, url: str) -> ProviderResult:
        """Perform the lookup. May raise ProviderError or requests exceptions."""

    def lookup(self, url: str) -> ProviderResult:
        if not self.is_configured():
            return self._result(
                LookupStatus.NOT_CONFIGURED, "No credentials configured, so this service was not queried."
            )
        with self._lock:
            if time.monotonic() < self._cooldown_until and self._cooldown_status:
                return self._result(
                    self._cooldown_status,
                    "Skipped: the service recently reported a quota or credential "
                    "problem. It will be retried automatically later.",
                )
        started = time.monotonic()
        try:
            result = self._query(url)
        except ProviderError as exc:
            result = self._result(exc.status, exc.detail)
        except requests.Timeout:
            result = self._result(LookupStatus.TIMEOUT, "The service did not respond in time.")
        except requests.RequestException as exc:
            logger.warning("%s request failed: %s", self.provider_id, type(exc).__name__)
            result = self._result(LookupStatus.ERROR, "The service could not be reached.")
        except (ValueError, KeyError, TypeError, AttributeError):
            result = self._result(
                LookupStatus.MALFORMED_RESPONSE, "The service returned a response that could not be interpreted."
            )
        result.latency_ms = int((time.monotonic() - started) * 1000)
        if result.status in (LookupStatus.QUOTA_EXCEEDED, LookupStatus.AUTH_ERROR):
            with self._lock:
                self._cooldown_until = time.monotonic() + self.cooldown_seconds
                self._cooldown_status = result.status
        return result

    def _result(self, status: LookupStatus, detail: str = "", threat_types: list[str] | None = None) -> ProviderResult:
        return ProviderResult(self.provider_id, self.display_name, status, threat_types or [], detail)

    @staticmethod
    def _status_from_http(response: requests.Response) -> None:
        """Translate HTTP error codes into ProviderError. Never includes response bodies,
        which could echo API keys."""
        code = response.status_code
        if code == 200:
            return
        if code in (401, 403):
            raise ProviderError(LookupStatus.AUTH_ERROR, f"The service rejected the credentials (HTTP {code}).")
        if code in (429, 509):
            raise ProviderError(LookupStatus.QUOTA_EXCEEDED, f"The service's request quota was exceeded (HTTP {code}).")
        raise ProviderError(LookupStatus.ERROR, f"The service returned HTTP {code}.")
