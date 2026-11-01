"""Lexical URL feature extraction (no network access).

:func:`extract_features` turns a :class:`ParsedURL` into a :class:`URLFeatures`
object containing

* ``numeric`` - a flat ``dict[str, float]`` with a fixed key order
  (:data:`NUMERIC_FEATURE_NAMES`). This exact vector is used both by the rule
  engine and by the machine-learning pipeline, so training and inference share
  one implementation.
* structured evidence (brand mentions, look-alike matches, keyword hits ...)
  consumed by the rule engine to produce human-readable findings.

None of these features is proof of phishing on its own; see
``docs/detection_methodology.md`` for the rationale and limitations of each.
"""

from __future__ import annotations

import math
import re
import unicodedata
from collections import Counter
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, unquote

from phishguard.detector.brands import BRAND_BY_ALIAS, BRAND_BY_TOKEN, official_brands_for
from phishguard.detector.url_parser import ParsedURL, is_private_or_reserved

# --- Lexicons ---------------------------------------------------------------

CREDENTIAL_KEYWORDS: frozenset[str] = frozenset(
    {
        "login",
        "logon",
        "signin",
        "sign-in",
        "log-in",
        "verify",
        "verification",
        "validate",
        "account",
        "accounts",
        "update",
        "secure",
        "security",
        "banking",
        "confirm",
        "password",
        "passwd",
        "credential",
        "credentials",
        "wallet",
        "unlock",
        "suspend",
        "suspended",
        "billing",
        "invoice",
        "payment",
        "authenticate",
        "auth",
        "recover",
        "recovery",
        "reset",
        "kyc",
        "webscr",
        "ebayisapi",
        "refund",
        "claim",
        "prize",
        "reactivate",
        "restore",
        "otp",
        "2fa",
        "mfa",
        "seed",
        "airdrop",
    }
)

# Words that commonly accompany a brand name in impersonating hostnames
# ("paypal-secure", "securepaypal", "applesupport").
BRAND_AFFIXES: frozenset[str] = frozenset(
    {
        "login",
        "signin",
        "secure",
        "security",
        "verify",
        "verification",
        "support",
        "account",
        "accounts",
        "update",
        "service",
        "services",
        "help",
        "helpdesk",
        "online",
        "auth",
        "billing",
        "pay",
        "payment",
        "wallet",
        "id",
        "team",
        "center",
        "centre",
        "alert",
        "alerts",
        "mail",
        "my",
        "web",
        "app",
        "official",
        "customer",
        "care",
        "unlock",
        "recovery",
        "confirm",
        "check",
        "access",
        "portal",
        "user",
        "client",
        "info",
        "notice",
    }
)

# Ordinary words within edit distance 1 of a protected brand token. They must
# not be reported as typosquats.
TYPO_ALLOWLIST: frozenset[str] = frozenset(
    {
        "finance",
        "cloud",
        "clouds",
        "twister",
        "outlooks",
        "dropbear",
        "github",
        "spotty",
        "netflux",
        "gogle",
        "googly",
        "amazing",
        "amazons",
        "steamy",
        "linked",
    }
)

URL_SHORTENERS: frozenset[str] = frozenset(
    {
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "ow.ly",
        "is.gd",
        "buff.ly",
        "cutt.ly",
        "rebrand.ly",
        "tiny.cc",
        "shorturl.at",
        "rb.gy",
        "bit.do",
        "s.id",
        "t.ly",
        "v.gd",
        "lnkd.in",
        "qrco.de",
        "shorturl.gg",
        "tinyurl.is",
        "urlz.fr",
        "clck.ru",
        "u.to",
    }
)

# Platform suffixes where anyone can publish content or open a tunnel.
FREE_HOSTING_SUFFIXES: frozenset[str] = frozenset(
    {
        "github.io",
        "gitlab.io",
        "pages.dev",
        "workers.dev",
        "netlify.app",
        "vercel.app",
        "herokuapp.com",
        "firebaseapp.com",
        "web.app",
        "appspot.com",
        "azurewebsites.net",
        "blogspot.com",
        "wordpress.com",
        "weebly.com",
        "wixsite.com",
        "glitch.me",
        "repl.co",
        "onrender.com",
        "fly.dev",
        "000webhostapp.com",
        "ngrok.io",
        "ngrok-free.app",
        "trycloudflare.com",
        "r2.dev",
        "s3.amazonaws.com",
        "duckdns.org",
        "no-ip.org",
        "ddns.net",
    }
)

# TLDs over-represented in abuse reporting. Low weight only: most sites on
# these TLDs are legitimate.
ELEVATED_ABUSE_TLDS: frozenset[str] = frozenset(
    {
        "zip",
        "mov",
        "top",
        "tk",
        "ml",
        "ga",
        "cf",
        "gq",
        "cyou",
        "icu",
        "buzz",
        "rest",
        "monster",
        "sbs",
        "cfd",
        "click",
        "country",
        "kim",
        "work",
        "xin",
        "bond",
        "lol",
        "quest",
    }
)

REDIRECT_PARAMS: frozenset[str] = frozenset(
    {
        "url",
        "redirect",
        "redirect_url",
        "redirect_uri",
        "redir",
        "next",
        "target",
        "dest",
        "destination",
        "rurl",
        "return",
        "returnurl",
        "return_url",
        "returnto",
        "goto",
        "continue",
        "u",
        "r",
        "link",
        "out",
        "to",
        "forward",
    }
)

EXECUTABLE_EXTENSIONS: frozenset[str] = frozenset(
    {
        "exe",
        "scr",
        "msi",
        "bat",
        "cmd",
        "vbs",
        "vbe",
        "jar",
        "apk",
        "ps1",
        "hta",
        "dll",
        "lnk",
        "pif",
        "cpl",
        "iso",
        "img",
        "js",
        "jse",
        "wsf",
        "msix",
        "appx",
        "dmg",
        "pkg",
    }
)
ARCHIVE_EXTENSIONS: frozenset[str] = frozenset({"zip", "rar", "7z", "tar", "gz", "cab", "ace"})

# Visually confusable characters mapped to the ASCII letter they imitate.
_CONFUSABLES: dict[str, str] = {
    # Cyrillic
    "а": "a",
    "в": "b",
    "е": "e",
    "ё": "e",
    "ѕ": "s",
    "і": "i",
    "ї": "i",
    "ј": "j",
    "о": "o",
    "р": "p",
    "с": "c",
    "у": "y",
    "х": "x",
    "ӏ": "l",
    "һ": "h",
    "ԁ": "d",
    "ԛ": "q",
    "ԝ": "w",
    "к": "k",
    "м": "m",
    "н": "h",
    "т": "t",
    "п": "n",
    "ь": "b",
    "г": "r",
    # Greek
    "α": "a",
    "β": "b",
    "ε": "e",
    "ι": "i",
    "κ": "k",
    "ν": "v",
    "ο": "o",
    "ρ": "p",
    "τ": "t",
    "υ": "u",
    "χ": "x",
    "ω": "w",
    # Armenian
    "օ": "o",
    "ո": "n",
    "ս": "u",
    "հ": "h",
    "ց": "g",
    "ք": "p",
    # Latin look-alikes
    "ı": "i",
    "ɩ": "i",
    "ł": "l",
    "ɡ": "g",
    "ɑ": "a",
    "ʀ": "r",
    "ꞵ": "b",
    "ℓ": "l",
}

# ASCII look-alike substitutions used in typosquats. Applied symmetrically to
# both the candidate and the brand token, so "paypa1" ~ "paypal".
_ASCII_SKELETON: tuple[tuple[str, str], ...] = (
    ("rn", "m"),
    ("vv", "w"),
    ("0", "o"),
    ("1", "l"),
    ("i", "l"),
    ("|", "l"),
    ("3", "e"),
    ("5", "s"),
    ("$", "s"),
    ("@", "a"),
    ("4", "a"),
)

_PERCENT_RE = re.compile(r"%[0-9A-Fa-f]{2}")
_DOUBLE_ENCODED_RE = re.compile(r"%25[0-9A-Fa-f]{2}")
_DOMAIN_LIKE_RE = re.compile(r"(?:[a-z0-9\-]+\.)+[a-z]{2,63}", re.IGNORECASE)
_SPLIT_TOKENS_RE = re.compile(r"[^a-z0-9]+")
_SAFE_SPECIALS = set("/:.-?=&_")

NUMERIC_FEATURE_NAMES: tuple[str, ...] = (
    "url_length",
    "host_length",
    "path_length",
    "query_length",
    "num_dots_host",
    "num_hyphens_host",
    "num_hyphens_url",
    "num_digits_host",
    "num_digits_url",
    "num_special_chars",
    "num_subdomains",
    "max_label_length",
    "digit_ratio_host",
    "registrable_label_length",
    "registrable_label_entropy",
    "num_hyphens_registrable",
    "is_ip",
    "ip_obfuscated",
    "is_private_address",
    "has_credentials",
    "userinfo_domain_like",
    "is_https",
    "nonstandard_port",
    "is_idn",
    "idna_strict_invalid",
    "has_mixed_script",
    "host_percent_encoded",
    "num_percent_encodings",
    "has_double_encoding",
    "num_query_params",
    "path_depth",
    "has_dot_segments",
    "has_double_slash_in_path",
    "backslash_in_path",
    "credential_keywords_host",
    "credential_keywords_path",
    "brand_in_subdomain",
    "brand_in_registrable_nonofficial",
    "brand_in_path",
    "brand_lookalike",
    "is_official_brand_domain",
    "is_shortener",
    "is_free_hosting",
    "elevated_abuse_tld",
    "has_redirect_param",
    "has_executable_extension",
    "has_archive_extension",
)


@dataclass(frozen=True)
class BrandMention:
    brand: str  # token
    brand_name: str
    location: str  # "subdomain" | "registrable" | "path" | "userinfo"
    evidence: str


@dataclass(frozen=True)
class LookalikeMatch:
    brand: str
    brand_name: str
    label: str
    method: str  # "homoglyph" | "ascii-substitution" | "edit-distance"
    whole_domain: bool = False  # the entire registered-domain label imitates the brand


@dataclass
class URLFeatures:
    numeric: dict[str, float]
    official_brands: set[str] = field(default_factory=set)
    brand_mentions: list[BrandMention] = field(default_factory=list)
    lookalikes: list[LookalikeMatch] = field(default_factory=list)
    mixed_script_labels: list[tuple[str, list[str]]] = field(default_factory=list)
    keywords_host: list[str] = field(default_factory=list)
    keywords_path: list[str] = field(default_factory=list)
    redirect_params: list[str] = field(default_factory=list)
    file_extension: str | None = None
    shortener: str | None = None
    free_hosting_suffix: str | None = None
    userinfo_domain: str | None = None
    official_domain_in_path: str | None = None
    official_domain_in_subdomain: str | None = None
    tld: str = ""

    def as_dict(self) -> dict[str, object]:
        """JSON-serialisable summary (no raw credentials)."""
        return {
            "numeric": self.numeric,
            "official_brands": sorted(self.official_brands),
            "brand_mentions": [m.__dict__ for m in self.brand_mentions],
            "lookalikes": [m.__dict__ for m in self.lookalikes],
            "mixed_script_labels": [
                {"label": label, "scripts": scripts} for label, scripts in self.mixed_script_labels
            ],
            "keywords_host": self.keywords_host,
            "keywords_path": self.keywords_path,
            "redirect_params": self.redirect_params,
            "file_extension": self.file_extension,
            "shortener": self.shortener,
            "free_hosting_suffix": self.free_hosting_suffix,
            "tld": self.tld,
        }


# --- Helpers ----------------------------------------------------------------


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def char_script(ch: str) -> str:
    """Coarse Unicode script name of a letter (e.g. LATIN, CYRILLIC, GREEK)."""
    try:
        name = unicodedata.name(ch)
    except ValueError:
        return "UNKNOWN"
    first = name.split(" ")[0]
    if first in {"CJK", "HIRAGANA", "KATAKANA", "HANGUL"}:
        return "CJK"
    return first


def label_scripts(label: str) -> list[str]:
    return sorted({char_script(ch) for ch in label if ch.isalpha()})


def _strip_marks(text: str) -> str:
    decomposed = unicodedata.normalize("NFKD", text)
    return "".join(ch for ch in decomposed if not unicodedata.combining(ch))


def skeleton(text: str) -> str:
    """Map ``text`` to a canonical form where visually similar strings collide."""
    mapped = "".join(_CONFUSABLES.get(ch, ch) for ch in text.lower())
    mapped = _strip_marks(mapped).lower()
    for src, dst in _ASCII_SKELETON:
        mapped = mapped.replace(src, dst)
    return mapped


_BRAND_SKELETONS: dict[str, str] = {token: skeleton(token) for token in BRAND_BY_TOKEN}


def damerau_levenshtein_le1(a: str, b: str) -> bool:
    """True when ``a`` and ``b`` differ by exactly one edit (incl. transposition)."""
    if a == b:
        return False
    la, lb = len(a), len(b)
    if abs(la - lb) > 1:
        return False
    if la == lb:
        diffs = [i for i in range(la) if a[i] != b[i]]
        if len(diffs) == 1:
            return True
        return (
            len(diffs) == 2 and diffs[1] == diffs[0] + 1 and a[diffs[0]] == b[diffs[1]] and a[diffs[1]] == b[diffs[0]]
        )
    if la > lb:
        a, b = b, a
    # b is one character longer than a
    return any(b[:i] + b[i + 1 :] == a for i in range(len(b)))


def _tokens(text: str) -> list[str]:
    return [t for t in _SPLIT_TOKENS_RE.split(text.lower()) if t]


def _brand_in_label(label: str) -> str | None:
    """Return a brand token if ``label`` impersonates it via token or affix."""
    parts = [p for p in re.split(r"[-_\d]+", label) if p]
    for part in parts:
        if part in BRAND_BY_TOKEN:
            return part
        if part in BRAND_BY_ALIAS:
            return BRAND_BY_ALIAS[part].token
        for token in BRAND_BY_TOKEN:
            if part.startswith(token) and part[len(token) :] in BRAND_AFFIXES:
                return token
            if part.endswith(token) and part[: -len(token)] in BRAND_AFFIXES:
                return token
    return None


def _find_lookalikes(
    unicode_labels: list[str], ascii_labels: list[str], registrable_ascii: str = ""
) -> list[LookalikeMatch]:
    matches: list[LookalikeMatch] = []
    seen: set[tuple[str, str]] = set()
    for u_label, a_label in zip(unicode_labels, ascii_labels, strict=False):
        is_unicode = not u_label.isascii()
        candidates = [p for p in re.split(r"[-_]+", u_label) if p] or [u_label]
        for part in candidates:
            part_skeleton = skeleton(part)
            for token, brand in BRAND_BY_TOKEN.items():
                if part == token:
                    continue
                method = None
                if part_skeleton == _BRAND_SKELETONS[token]:
                    method = "homoglyph" if is_unicode else "ascii-substitution"
                elif (
                    not is_unicode
                    and len(token) >= 6
                    and len(part) >= 5
                    and part not in TYPO_ALLOWLIST
                    and damerau_levenshtein_le1(part, token)
                ):
                    method = "edit-distance"
                if method and (token, a_label) not in seen:
                    seen.add((token, a_label))
                    whole = a_label == registrable_ascii and part == u_label
                    matches.append(LookalikeMatch(token, brand.name, u_label, method, whole))
    return matches


# --- Main entry point -------------------------------------------------------


def extract_features(parsed: ParsedURL) -> URLFeatures:
    url = parsed.normalized
    host = parsed.host_ascii
    is_domain = parsed.host_type == "domain"
    labels = list(parsed.labels)
    unicode_labels = parsed.host_unicode.split(".") if is_domain else []
    path = parsed.path
    query = parsed.query
    path_and_query = f"{path}?{query}" if query else path

    official = official_brands_for(parsed.registrable_domain, host) if is_domain else set()
    suffix_len = len(parsed.public_suffix.split(".")) if parsed.public_suffix else 0
    keep = max(len(labels) - suffix_len, 0)
    registrable_unicode = unicode_labels[keep - 1] if is_domain and keep and len(unicode_labels) >= keep else ""

    # --- Brand mentions ---
    mentions: list[BrandMention] = []
    if is_domain:
        for sub in parsed.subdomain_labels:
            token = _brand_in_label(sub)
            if token and token not in official:
                mentions.append(BrandMention(token, BRAND_BY_TOKEN[token].name, "subdomain", sub))
        token = _brand_in_label(parsed.registrable_label)
        if token and token not in official:
            mentions.append(BrandMention(token, BRAND_BY_TOKEN[token].name, "registrable", parsed.registrable_domain))

    lowered_pq = unquote(path_and_query).lower()
    path_tokens = set(_tokens(lowered_pq))
    for token, brand in BRAND_BY_TOKEN.items():
        if token in official:
            continue
        if token in path_tokens:
            mentions.append(BrandMention(token, brand.name, "path", token))

    official_domain_in_path = None
    for match in _DOMAIN_LIKE_RE.finditer(lowered_pq):
        candidate = match.group(0).lower().lstrip("-.")
        for token, brand in BRAND_BY_TOKEN.items():
            if token in official:
                continue
            if any(candidate == d or candidate.endswith("." + d) for d in brand.official_domains):
                official_domain_in_path = candidate
                break
        if official_domain_in_path:
            break

    # --- Userinfo deception ("https://paypal.com@evil.example/") ---
    userinfo_domain = None
    if parsed.userinfo:
        found = _DOMAIN_LIKE_RE.search(parsed.userinfo)
        if found:
            userinfo_domain = found.group(0).lower()
            token = _brand_in_label(userinfo_domain.split(".")[0])
            if token is None:
                for t, brand in BRAND_BY_TOKEN.items():
                    if any(userinfo_domain == d or userinfo_domain.endswith("." + d) for d in brand.official_domains):
                        token = t
                        break
            if token and token not in official:
                mentions.append(BrandMention(token, BRAND_BY_TOKEN[token].name, "userinfo", userinfo_domain))

    # --- Official brand domain spelled out inside the subdomains ---
    # ("paypal.com.account-verify.example.net")
    official_domain_in_subdomain = None
    if is_domain and parsed.subdomain_labels:
        sub = "." + ".".join(parsed.subdomain_labels) + "."
        for token, brand in BRAND_BY_TOKEN.items():
            if token in official:
                continue
            hit = next((d for d in brand.official_domains if f".{d}." in sub), None)
            if hit:
                official_domain_in_subdomain = hit
                break

    # --- Homoglyphs / typosquats ---
    lookalikes = (
        _find_lookalikes(unicode_labels[:keep], labels[:keep], parsed.registrable_label) if is_domain and keep else []
    )
    lookalikes = [m for m in lookalikes if m.brand not in official]

    mixed: list[tuple[str, list[str]]] = []
    for label in unicode_labels:
        scripts = label_scripts(label)
        if len(scripts) > 1 and not set(scripts) <= {"LATIN", "CJK"}:
            mixed.append((label, scripts))

    # --- Keywords ---
    host_tokens: list[str] = []
    for label in labels[:keep] if is_domain else []:
        host_tokens.extend(_tokens(label))
    keywords_host = sorted({t for t in host_tokens if t in CREDENTIAL_KEYWORDS}) if not official else []
    keywords_path = sorted({t for t in path_tokens if t in CREDENTIAL_KEYWORDS})

    # --- Query / path structure ---
    try:
        params = parse_qsl(query, keep_blank_values=True)
    except ValueError:
        params = []
    redirect_params = sorted(
        {
            k.lower()
            for k, v in params
            if k.lower() in REDIRECT_PARAMS and re.match(r"^(https?:)?//", unquote(v).strip(), re.I)
        }
    )
    last_segment = path.rstrip("/").rsplit("/", 1)[-1]
    ext = last_segment.rsplit(".", 1)[-1].lower() if "." in last_segment else None
    is_exec = ext in EXECUTABLE_EXTENSIONS if ext else False
    is_archive = ext in ARCHIVE_EXTENSIONS if ext else False

    shortener = parsed.registrable_domain if parsed.registrable_domain in URL_SHORTENERS else None
    if shortener is None and host in URL_SHORTENERS:
        shortener = host
    free_hosting = parsed.public_suffix if parsed.public_suffix in FREE_HOSTING_SUFFIXES else None
    tld = labels[-1] if is_domain and labels else ""

    special = sum(1 for ch in url if not ch.isalnum() and ch not in _SAFE_SPECIALS)
    digits_host = sum(ch.isdigit() for ch in host)

    numeric: dict[str, float] = {
        "url_length": len(url),
        "host_length": len(host),
        "path_length": len(path),
        "query_length": len(query),
        "num_dots_host": host.count("."),
        "num_hyphens_host": host.count("-"),
        "num_hyphens_url": url.count("-"),
        "num_digits_host": digits_host,
        "num_digits_url": sum(ch.isdigit() for ch in url),
        "num_special_chars": special,
        "num_subdomains": len(parsed.subdomain_labels),
        "max_label_length": max((len(label) for label in labels), default=0),
        "digit_ratio_host": round(digits_host / len(host), 4) if host else 0.0,
        "registrable_label_length": len(parsed.registrable_label),
        "registrable_label_entropy": round(shannon_entropy(parsed.registrable_label), 4),
        "num_hyphens_registrable": registrable_unicode.count("-"),
        "is_ip": float(parsed.is_ip),
        "ip_obfuscated": float(parsed.ip_obfuscated),
        "is_private_address": float(is_private_or_reserved(parsed)),
        "has_credentials": float(parsed.has_credentials),
        "userinfo_domain_like": float(userinfo_domain is not None),
        "is_https": float(parsed.scheme == "https"),
        "nonstandard_port": float(parsed.nonstandard_port),
        "is_idn": float(parsed.is_idn),
        "idna_strict_invalid": float(not parsed.idna_strict_valid),
        "has_mixed_script": float(bool(mixed)),
        "host_percent_encoded": float(parsed.host_percent_encoded),
        "num_percent_encodings": len(_PERCENT_RE.findall(path_and_query)),
        "has_double_encoding": float(bool(_DOUBLE_ENCODED_RE.search(path_and_query))),
        "num_query_params": len(params),
        "path_depth": len([s for s in path.split("/") if s]),
        "has_dot_segments": float(bool(re.search(r"(^|/)\.\.?(/|$)", path))),
        "has_double_slash_in_path": float("//" in path),
        "backslash_in_path": float(parsed.backslash_in_path),
        "credential_keywords_host": len(keywords_host),
        "credential_keywords_path": len(keywords_path),
        "brand_in_subdomain": float(any(m.location == "subdomain" for m in mentions)),
        "brand_in_registrable_nonofficial": float(any(m.location == "registrable" for m in mentions)),
        "brand_in_path": float(any(m.location == "path" for m in mentions)),
        "brand_lookalike": float(bool(lookalikes)),
        "is_official_brand_domain": float(bool(official)),
        "is_shortener": float(shortener is not None),
        "is_free_hosting": float(free_hosting is not None),
        "elevated_abuse_tld": float(tld in ELEVATED_ABUSE_TLDS),
        "has_redirect_param": float(bool(redirect_params)),
        "has_executable_extension": float(is_exec),
        "has_archive_extension": float(is_archive),
    }
    # Keep a stable, explicit order for ML.
    numeric = {name: float(numeric[name]) for name in NUMERIC_FEATURE_NAMES}

    return URLFeatures(
        numeric=numeric,
        official_brands=official,
        brand_mentions=mentions,
        lookalikes=lookalikes,
        mixed_script_labels=mixed,
        keywords_host=keywords_host,
        keywords_path=keywords_path,
        redirect_params=redirect_params,
        file_extension=ext if (is_exec or is_archive) else None,
        shortener=shortener,
        free_hosting_suffix=free_hosting,
        userinfo_domain=userinfo_domain,
        official_domain_in_path=official_domain_in_path,
        official_domain_in_subdomain=official_domain_in_subdomain,
        tld=tld,
    )
