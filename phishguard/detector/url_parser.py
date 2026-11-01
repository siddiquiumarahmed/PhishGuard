"""Strict, offline URL parsing and conservative normalisation.

Nothing in this module performs network I/O: no DNS lookups and no HTTP
requests. Submitted URLs are only ever treated as strings.

Design notes
------------
* The authority section is split by hand (rather than relying solely on
  :func:`urllib.parse.urlsplit`) so behaviour is explicit for the tricks
  phishing links rely on: ``user@host`` confusion, backslashes, percent-encoded
  hostnames and obfuscated IPv4 notation (``http://3232235777/``).
* IPv4 parsing follows the WHATWG URL Standard, which is what browsers do, so
  an obfuscated address is analysed as the address a browser would contact.
* The *original* submitted value is preserved untouched; ``normalized`` is the
  analysis representation (credentials and fragment removed, host lowercased
  and converted to ASCII/punycode, default port dropped). Paths and queries are
  **not** percent-decoded or rewritten.
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Literal
from urllib.parse import unquote

import idna

from phishguard.detector.public_suffix import split_domain

SUPPORTED_SCHEMES = ("http", "https")
DEFAULT_PORTS = {"http": 80, "https": 443}
DEFAULT_MAX_URL_LENGTH = 2048

_SCHEME_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.\-]*):")
_ASCII_LABEL_RE = re.compile(r"^[a-z0-9_](?:[a-z0-9_\-]*[a-z0-9_])?$")
_TLD_RE = re.compile(r"^(?:[a-z]{2,63}|xn--[a-z0-9\-]{1,59})$")

# Invisible / bidirectional formatting characters frequently used to disguise
# links (e.g. U+202E RIGHT-TO-LEFT OVERRIDE, zero-width joiners).
_INVISIBLE_CHARS = {
    "​",
    "‌",
    "‍",
    "‎",
    "‏",
    "⁠",
    "﻿",
    "‪",
    "‫",
    "‬",
    "‭",
    "‮",
    "⁦",
    "⁧",
    "⁨",
    "⁩",
    "­",
}

HostType = Literal["domain", "ipv4", "ipv6"]


class URLValidationError(ValueError):
    """Raised when a submitted value is not an acceptable HTTP(S) URL.

    ``code`` is a stable machine-readable identifier; ``message`` is safe to
    show to end users (it never echoes the submitted value).
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class ParsedURL:
    # The raw submitted value may contain passwords or tokens, so it is kept
    # out of repr() to avoid accidental exposure in logs or tracebacks.
    original: str = field(repr=False)
    normalized: str = field(repr=False)
    scheme: str
    host_ascii: str
    host_unicode: str
    host_type: HostType
    port: int | None
    effective_port: int
    path: str = field(repr=False)
    query: str = field(repr=False)
    fragment: str = field(repr=False)
    has_fragment: bool
    username: str | None
    has_password: bool
    labels: tuple[str, ...]
    public_suffix: str
    registrable_domain: str
    registrable_label: str
    subdomain_labels: tuple[str, ...]
    is_idn: bool
    idna_strict_valid: bool
    ip_obfuscated: bool = False
    host_percent_encoded: bool = False
    had_trailing_dot: bool = False
    backslash_in_path: bool = False
    notes: tuple[str, ...] = field(default_factory=tuple)
    # Full decoded userinfo (may include a password). Used only for in-memory
    # analysis; never persisted, logged or rendered.
    userinfo: str | None = field(default=None, repr=False)

    @property
    def has_credentials(self) -> bool:
        return self.username is not None

    @property
    def is_ip(self) -> bool:
        return self.host_type in ("ipv4", "ipv6")

    @property
    def nonstandard_port(self) -> bool:
        return self.port is not None and self.port != DEFAULT_PORTS[self.scheme]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def parse_url(raw: object, max_length: int = DEFAULT_MAX_URL_LENGTH) -> ParsedURL:
    """Validate ``raw`` and return a :class:`ParsedURL`.

    Raises :class:`URLValidationError` with a user-facing message on failure.
    """
    if not isinstance(raw, str):
        raise URLValidationError("invalid_type", "The URL must be provided as text.")

    candidate = raw.strip()
    if not candidate:
        raise URLValidationError("empty", "Enter a URL to scan.")
    if len(candidate) > max_length:
        raise URLValidationError("too_long", f"The URL is longer than the {max_length}-character limit.")
    _reject_bad_characters(candidate)

    scheme, rest = _split_scheme(candidate)

    # Split authority from path/query/fragment.
    end = len(rest)
    for delimiter in ("/", "?", "#"):
        idx = rest.find(delimiter)
        if idx != -1:
            end = min(end, idx)
    authority, remainder = rest[:end], rest[end:]

    if "\\" in authority:
        raise URLValidationError(
            "backslash_in_authority",
            "The address contains a backslash before the path. Browsers interpret this "
            "inconsistently and it is a known trick for disguising the real destination. "
            "Treat this link as untrustworthy.",
        )

    userinfo, hostport = _split_userinfo(authority)
    username, has_password = _parse_userinfo(userinfo)
    userinfo_decoded = unquote(userinfo) if userinfo is not None else None
    host_raw, port = _split_host_port(hostport)

    notes: list[str] = []
    host_percent_encoded = False
    if "%" in host_raw and not host_raw.startswith("["):
        host_percent_encoded = True
        host_raw = _percent_decode_host(host_raw)
        notes.append("Hostname was percent-encoded; it was decoded the way a browser would.")

    had_trailing_dot = False
    if host_raw.endswith(".") and not host_raw.startswith("["):
        host_raw = host_raw[:-1]
        had_trailing_dot = True
        notes.append("A trailing dot was removed from the hostname.")

    if not host_raw:
        raise URLValidationError("missing_host", "The URL does not contain a hostname.")

    host_ascii, host_unicode, host_type, ip_obfuscated, is_idn, strict_ok = _parse_host(host_raw)

    if port is not None and port == DEFAULT_PORTS[scheme]:
        notes.append(f"The default {scheme.upper()} port was removed during normalisation.")

    path, query, fragment, has_fragment = _split_remainder(remainder)
    backslash_in_path = "\\" in path

    labels: tuple[str, ...]
    if host_type == "domain":
        labels = tuple(host_ascii.split("."))
        parts = split_domain(host_ascii)
        public_suffix = parts.public_suffix
        registrable_domain = parts.registrable_domain
        registrable_label = parts.registrable_label
        subdomain_labels = parts.subdomain_labels
    else:
        labels = ()
        public_suffix = registrable_domain = registrable_label = ""
        subdomain_labels = ()

    normalized = _build_normalized(scheme, host_ascii, host_type, port, path, query)

    return ParsedURL(
        original=raw,
        normalized=normalized,
        scheme=scheme,
        host_ascii=host_ascii,
        host_unicode=host_unicode,
        host_type=host_type,
        port=port,
        effective_port=port if port is not None else DEFAULT_PORTS[scheme],
        path=path,
        query=query,
        fragment=fragment,
        has_fragment=has_fragment,
        username=username,
        has_password=has_password,
        userinfo=userinfo_decoded,
        labels=labels,
        public_suffix=public_suffix,
        registrable_domain=registrable_domain,
        registrable_label=registrable_label,
        subdomain_labels=subdomain_labels,
        is_idn=is_idn,
        idna_strict_valid=strict_ok,
        ip_obfuscated=ip_obfuscated,
        host_percent_encoded=host_percent_encoded,
        had_trailing_dot=had_trailing_dot,
        backslash_in_path=backslash_in_path,
        notes=tuple(notes),
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _reject_bad_characters(value: str) -> None:
    for ch in value:
        if ch in _INVISIBLE_CHARS:
            raise URLValidationError(
                "invisible_characters",
                "The URL contains invisible formatting characters, which are often used to "
                "disguise where a link really goes. Treat this link as untrustworthy.",
            )
        category = unicodedata.category(ch)
        if category == "Cc":
            raise URLValidationError("control_characters", "The URL contains control characters.")
        if ch.isspace():
            raise URLValidationError(
                "contains_whitespace",
                "The URL contains spaces. Real addresses encode spaces as %20; "
                "check that you copied the whole link correctly.",
            )


def _split_scheme(candidate: str) -> tuple[str, str]:
    match = _SCHEME_RE.match(candidate)
    after_colon = candidate[match.end() :] if match else ""
    # "example.com:8080/path" or "localhost:5000" look like a scheme to a naive
    # parser; treat them as a missing scheme instead.
    if not match or "." in match.group(1) or re.match(r"^\d", after_colon):
        raise URLValidationError(
            "missing_scheme",
            "Include the scheme at the start of the address, for example https://example.com.",
        )
    scheme = match.group(1).lower()
    if scheme not in SUPPORTED_SCHEMES:
        raise URLValidationError(
            "unsupported_scheme",
            "Only http:// and https:// web addresses can be scanned.",
        )
    if not after_colon.startswith("//"):
        raise URLValidationError(
            "malformed",
            f"A {scheme}: address must continue with // followed by a hostname.",
        )
    return scheme, after_colon[2:]


def _split_userinfo(authority: str) -> tuple[str | None, str]:
    if "@" not in authority:
        return None, authority
    userinfo, _, hostport = authority.rpartition("@")
    return userinfo, hostport


def _parse_userinfo(userinfo: str | None) -> tuple[str | None, bool]:
    if userinfo is None:
        return None, False
    username, sep, _password = userinfo.partition(":")
    # The password itself is deliberately discarded and never stored.
    return unquote(username), bool(sep)


def _split_host_port(hostport: str) -> tuple[str, int | None]:
    if hostport.startswith("["):
        close = hostport.find("]")
        if close == -1:
            raise URLValidationError("invalid_ipv6", "The IPv6 address is missing its closing ']'.")
        host = hostport[: close + 1]
        after = hostport[close + 1 :]
        if after == "":
            return host, None
        if not after.startswith(":"):
            raise URLValidationError("invalid_host", "Unexpected characters after the IPv6 address.")
        return host, _parse_port(after[1:])

    if hostport.count(":") > 1:
        raise URLValidationError(
            "invalid_host",
            "The hostname contains more than one ':'. IPv6 addresses must be written in brackets, "
            "e.g. http://[2001:db8::1]/.",
        )
    host, sep, port_text = hostport.partition(":")
    return host, _parse_port(port_text) if sep else None


def _parse_port(port_text: str) -> int | None:
    if port_text == "":
        return None
    if not port_text.isdigit() or not port_text.isascii():
        raise URLValidationError("invalid_port", "The port must be a number between 1 and 65535.")
    port = int(port_text)
    if not 1 <= port <= 65535:
        raise URLValidationError("invalid_port", "The port must be a number between 1 and 65535.")
    return port


def _percent_decode_host(host: str) -> str:
    try:
        decoded = unquote(host, encoding="utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise URLValidationError("invalid_host", "The hostname contains invalid percent-encoding.") from exc
    if "%" in decoded or any(c in decoded for c in "/?#@\\:[] "):
        raise URLValidationError("invalid_host", "The hostname contains invalid percent-encoding.")
    _reject_bad_characters(decoded)
    return decoded


def _parse_host(host: str) -> tuple[str, str, HostType, bool, bool, bool]:
    """Return (ascii, unicode, type, ip_obfuscated, is_idn, idna_strict_valid)."""
    if host.startswith("["):
        inner = host[1:-1]
        if "%" in inner:
            raise URLValidationError("invalid_ipv6", "IPv6 zone identifiers are not supported.")
        try:
            address = ipaddress.IPv6Address(inner)
        except ValueError as exc:
            raise URLValidationError("invalid_ipv6", "The IPv6 address is malformed.") from exc
        text = f"[{address.compressed}]"
        return text, text, "ipv6", False, False, True

    lowered = host.lower()
    labels = lowered.split(".")

    if _ends_in_number(labels):
        ipv4, obfuscated = _parse_whatwg_ipv4(labels)
        return ipv4, ipv4, "ipv4", obfuscated, False, True

    if lowered.isascii():
        _validate_ascii_labels(labels)
        unicode_labels = []
        is_idn = False
        for label in labels:
            if label.startswith("xn--"):
                is_idn = True
                unicode_labels.append(_decode_punycode_label(label))
            else:
                unicode_labels.append(label)
        _validate_tld(labels[-1])
        if len(labels) < 2 and lowered != "localhost":
            raise _not_fqdn()
        return lowered, ".".join(unicode_labels), "domain", False, is_idn, True

    # Internationalised hostname: UTS #46 / IDNA 2008 first, IDNA 2003 fallback
    # (browsers are more permissive than IDNA 2008, so a lenient fallback keeps
    # deceptive-but-reachable hostnames analysable).
    strict_ok = True
    try:
        ascii_host = idna.encode(host, uts46=True, transitional=False).decode("ascii")
    except (idna.IDNAError, UnicodeError):
        strict_ok = False
        try:
            ascii_host = host.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise URLValidationError(
                "invalid_hostname",
                "The hostname contains characters that are not allowed in domain names.",
            ) from exc
    ascii_labels = ascii_host.split(".")
    _validate_ascii_labels(ascii_labels)
    _validate_tld(ascii_labels[-1])
    if len(ascii_labels) < 2:
        raise _not_fqdn()
    unicode_host = ".".join(
        _decode_punycode_label(label) if label.startswith("xn--") else label for label in ascii_labels
    )
    return ascii_host, unicode_host, "domain", False, True, strict_ok


def _not_fqdn() -> URLValidationError:
    return URLValidationError("not_fqdn", "The hostname must be a full domain name such as example.com.")


def _validate_ascii_labels(labels: list[str]) -> None:
    total = len(".".join(labels))
    if total > 253:
        raise URLValidationError("invalid_hostname", "The hostname is longer than 253 characters.")
    for label in labels:
        if label == "":
            raise URLValidationError("invalid_hostname", "The hostname contains an empty label ('..').")
        if len(label) > 63:
            raise URLValidationError("invalid_hostname", "A part of the hostname is longer than 63 characters.")
        if not _ASCII_LABEL_RE.match(label):
            raise URLValidationError(
                "invalid_hostname",
                "The hostname contains characters that are not allowed in domain names, "
                "or a part of it starts or ends with a hyphen.",
            )


def _validate_tld(tld: str) -> None:
    if tld == "localhost":
        return
    if not _TLD_RE.match(tld):
        raise URLValidationError("invalid_tld", "The top-level domain (the part after the last dot) is not valid.")


def _decode_punycode_label(label: str) -> str:
    try:
        return idna.decode(label)
    except (idna.IDNAError, UnicodeError):
        try:
            return label.encode("ascii").decode("idna")
        except UnicodeError as exc:
            raise URLValidationError(
                "invalid_punycode", "The hostname contains malformed punycode (xn--) labels."
            ) from exc


# --- WHATWG IPv4 -----------------------------------------------------------


def _ends_in_number(labels: list[str]) -> bool:
    """WHATWG 'ends in a number' check: decides whether a host is parsed as IPv4."""
    if not labels or labels[-1] == "":
        return False
    last = labels[-1]
    if last.isascii() and last.isdigit():
        return True
    return _parse_ipv4_number(last) is not None


def _parse_ipv4_number(part: str) -> int | None:
    if part == "":
        return None
    radix = 10
    text = part
    if len(text) >= 2 and text[:2] in ("0x", "0X"):
        radix, text = 16, text[2:]
    elif len(text) >= 2 and text[0] == "0":
        radix, text = 8, text[1:]
    if text == "":
        return 0
    allowed = {10: "0123456789", 8: "01234567", 16: "0123456789abcdefABCDEF"}[radix]
    if not all(c in allowed for c in text):
        return None
    return int(text, radix)


def _parse_whatwg_ipv4(labels: list[str]) -> tuple[str, bool]:
    invalid = URLValidationError(
        "invalid_ip",
        "The hostname looks like an IP address but is not a valid one (each part of an IPv4 address must be 0-255).",
    )
    if len(labels) > 4:
        raise invalid
    numbers: list[int] = []
    for part in labels:
        value = _parse_ipv4_number(part)
        if value is None:
            raise URLValidationError(
                "invalid_hostname",
                "The hostname ends in a number but is not a valid IP address. Top-level domains cannot be numeric.",
            )
        numbers.append(value)
    if any(n > 255 for n in numbers[:-1]):
        raise invalid
    if numbers[-1] >= 256 ** (5 - len(numbers)):
        raise invalid
    address = numbers[-1]
    for i, n in enumerate(numbers[:-1]):
        address += n * 256 ** (3 - i)
    dotted = str(ipaddress.IPv4Address(address))
    canonical_form = len(labels) == 4 and all(p.isdigit() and (p == "0" or not p.startswith("0")) for p in labels)
    return dotted, not canonical_form


# --- Remainder / normalisation ---------------------------------------------


def _split_remainder(remainder: str) -> tuple[str, str, str, bool]:
    fragment = ""
    has_fragment = False
    if "#" in remainder:
        remainder, _, fragment = remainder.partition("#")
        has_fragment = True
    query = ""
    if "?" in remainder:
        remainder, _, query = remainder.partition("?")
    path = remainder or "/"
    return path, query, fragment, has_fragment


def _build_normalized(
    scheme: str, host_ascii: str, host_type: HostType, port: int | None, path: str, query: str
) -> str:
    netloc = host_ascii
    if port is not None and port != DEFAULT_PORTS[scheme]:
        netloc = f"{netloc}:{port}"
    url = f"{scheme}://{netloc}{path}"
    if query:
        url = f"{url}?{query}"
    return url


_LOCAL_NETWORKS = tuple(
    ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "::1/128",
        "::/128",
        "fc00::/7",
        "fe80::/10",
    )
)


def is_private_or_reserved(parsed: ParsedURL) -> bool:
    """True when the host is localhost or on a local/internal network range.

    Documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) are
    deliberately *not* treated as local, so they behave like public addresses
    in tests and examples.
    """
    if parsed.host_type == "domain":
        return parsed.host_ascii == "localhost" or parsed.host_ascii.endswith(".localhost")
    address = ipaddress.ip_address(parsed.host_ascii.strip("[]"))
    return any(address in network for network in _LOCAL_NETWORKS if network.version == address.version)
