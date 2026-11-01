"""Modular rule engine.

Each rule is a small function registered with :func:`rule`. A rule receives
the parsed URL and its extracted features and returns zero or more
:class:`Finding` objects. Rules carry their own rationale and limitations so
the methodology page and documentation are generated from the same source as
the detection logic.

Severity levels are *categorical*, not probabilities:

``info``     context only; never raises the verdict
``low``      weak signal; common on legitimate sites
``medium``   meaningful warning sign
``high``     strong indicator of deception
``critical`` near-unambiguous deception technique
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum

from phishguard.detector.brands import BRANDS
from phishguard.detector.url_features import LookalikeMatch, URLFeatures
from phishguard.detector.url_parser import ParsedURL

logger = logging.getLogger(__name__)


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    severity: Severity
    explanation: str
    evidence: tuple[str, ...] = ()
    recommendation: str | None = None
    category: str = "general"

    def to_dict(self) -> dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "explanation": self.explanation,
            "evidence": list(self.evidence),
            "recommendation": self.recommendation,
            "category": self.category,
        }


RuleFunc = Callable[[ParsedURL, URLFeatures], list[Finding]]


@dataclass(frozen=True)
class Rule:
    rule_id: str
    title: str
    category: str
    rationale: str
    limitations: str
    func: RuleFunc


@dataclass
class RuleEngineResult:
    findings: list[Finding]
    rules_evaluated: int
    rule_errors: list[str] = field(default_factory=list)

    @property
    def status(self) -> str:
        if self.rules_evaluated and len(self.rule_errors) >= self.rules_evaluated:
            return "failed"
        return "partial" if self.rule_errors else "ok"

    def count(self, severity: Severity) -> int:
        return sum(1 for f in self.findings if f.severity == severity)


RULES: list[Rule] = []


def rule(rule_id: str, title: str, category: str, rationale: str, limitations: str):
    def decorator(func: RuleFunc) -> RuleFunc:
        RULES.append(Rule(rule_id, title, category, rationale, limitations, func))
        return func

    return decorator


def _f(
    rule_id: str,
    title: str,
    severity: Severity,
    explanation: str,
    evidence: list[str] | tuple[str, ...] = (),
    recommendation: str | None = None,
    category: str = "general",
) -> Finding:
    return Finding(rule_id, title, severity, explanation, tuple(evidence), recommendation, category)


def evaluate(parsed: ParsedURL, features: URLFeatures, rules: list[Rule] | None = None) -> RuleEngineResult:
    """Run every registered rule. A failing rule is recorded, not fatal."""
    active = RULES if rules is None else rules
    findings: list[Finding] = []
    errors: list[str] = []
    for r in active:
        try:
            findings.extend(r.func(parsed, features))
        except Exception:
            logger.exception("Rule %s failed", r.rule_id)
            errors.append(r.rule_id)
    findings.sort(key=lambda f: (-f.severity.rank, f.rule_id))
    return RuleEngineResult(findings=findings, rules_evaluated=len(active), rule_errors=errors)


VERIFY_INDEPENDENTLY = (
    "Do not enter passwords or payment details. Type the organisation's address yourself "
    "or use its official app instead of following this link."
)

# ---------------------------------------------------------------------------
# URL structure
# ---------------------------------------------------------------------------


@rule(
    "PG-URL-001",
    "Credentials embedded in the URL",
    "structure",
    rationale="Browsers ignore or warn about user:password@ prefixes; legitimate links almost never "
    "use them, but phishing links use them to push the real hostname out of view.",
    limitations="Some internal tools and FTP-era links still embed credentials; these will be flagged.",
)
def _credentials(parsed: ParsedURL, features: URLFeatures) -> list[Finding]:
    if not parsed.has_credentials or features.userinfo_domain:
        return []
    detail = "a username and password" if parsed.has_password else "a username"
    return [
        _f(
            "PG-URL-001",
            "Credentials embedded in the URL",
            Severity.MEDIUM,
            f"The link contains {detail} before the hostname. Modern websites do not use this "
            "format, and it can be used to make a link look like it belongs to someone else.",
            [f"Real destination host: {parsed.host_unicode}"],
            "Check the hostname after the '@' sign — that is the site you would actually visit.",
            "structure",
        )
    ]


@rule(
    "PG-URL-002",
    "Fake hostname placed before '@'",
    "deception",
    rationale="'https://trusted.example@attacker.example/' visits attacker.example. Placing a "
    "domain name before '@' has no legitimate use and is a classic disguise.",
    limitations="Detection relies on the text before '@' looking like a domain name.",
)
def _userinfo_disguise(parsed: ParsedURL, features: URLFeatures) -> list[Finding]:
    if not features.userinfo_domain:
        return []
    brand = next((m for m in features.brand_mentions if m.location == "userinfo"), None)
    severity = Severity.CRITICAL if brand else Severity.HIGH
    title = f"Disguised as {brand.brand_name} using '@'" if brand else "Fake hostname placed before '@'"
    return [
        _f(
            "PG-URL-002",
            title,
            severity,
            f"The address shows '{features.userinfo_domain}' before an '@' sign, but browsers treat that "
            f"part as a username. The link actually leads to '{parsed.host_unicode}'.",
            [f"Displayed name: {features.userinfo_domain}", f"Actual host: {parsed.host_unicode}"],
            VERIFY_INDEPENDENTLY,
            "deception",
        )
    ]


@rule(
    "PG-LEN-001",
    "Unusually long URL",
    "structure",
    rationale="Very long links can hide the real hostname on small screens and are common in "
    "phishing kits that append tracking or victim identifiers.",
    limitations="Search results, analytics and single sign-on links are often long and legitimate. Low severity only.",
)
def _long_url(parsed: ParsedURL, features: URLFeatures) -> list[Finding]:
    length = int(features.numeric["url_length"])
    host_len = int(features.numeric["host_length"])
    out = []
    if length > 200:
        out.append(
            _f(
                "PG-LEN-001",
                "Unusually long URL",
                Severity.LOW,
                "The link is very long. Long links are common on legitimate sites too, so this "
                "only matters in combination with other warning signs.",
                [f"Length: {length} characters"],
                category="structure",
            )
        )
    if host_len > 60:
        out.append(
            _f(
                "PG-LEN-001",
                "Unusually long hostname",
                Severity.LOW,
                "The hostname itself is unusually long, which can push the real domain name out "
                "of view in the address bar.",
                [f"Hostname length: {host_len} characters"],
                category="structure",
            )
        )
    return out


# ---------------------------------------------------------------------------
# Hostname
# ---------------------------------------------------------------------------


@rule(
    "PG-HOST-001",
    "Raw IP address instead of a domain name",
    "host",
    rationale="Legitimate public services almost always use domain names. Raw IP addresses avoid "
    "domain registration and hide who operates the site.",
    limitations="Routers, development servers and some APIs are legitimately reached by IP.",
)
def _ip_host(parsed: ParsedURL, features: URLFeatures) -> list[Finding]:
    if not parsed.is_ip or features.numeric["is_private_address"]:
        return []
    return [
        _f(
            "PG-HOST-001",
            "Raw IP address instead of a domain name",
            Severity.MEDIUM,
            "The link points to a numeric IP address rather than a named website. Legitimate "
            "organisations rarely ask you to sign in or pay on such pages.",
            [f"Host: {parsed.host_ascii}"],
            VERIFY_INDEPENDENTLY,
            "host",
        )
    ]


@rule(
    "PG-HOST-002",
    "Obfuscated IP address notation",
    "deception",
    rationale="Decimal, hexadecimal, octal or shortened IPv4 notation (e.g. http://3232235777/) is "
    "accepted by browsers but has no legitimate use in shared links; it exists to hide "
    "the destination.",
    limitations="None known for shared links.",
)
def _ip_obfuscated(parsed: ParsedURL, features: URLFeatures) -> list[Finding]:
    if not parsed.ip_obfuscated:
        return []
    return [
        _f(
            "PG-HOST-002",
            "Obfuscated IP address notation",
            Severity.HIGH,
            "The hostname is an IP address written in an unusual numeric form so it does not look "
            "like an address. Browsers still connect to it.",
            [f"Browsers resolve this to: {parsed.host_ascii}"],
            VERIFY_INDEPENDENTLY,
            "deception",
        )
    ]


@rule(
    "PG-HOST-003",
    "Percent-encoded hostname",
    "deception",
    rationale="Browsers decode %XX sequences in hostnames, so encoding letters of a domain only "
    "serves to hide it from people and simple filters.",
    limitations="None known for shared links.",
)
def _host_encoded(parsed: ParsedURL, features: URLFeatures) -> list[Finding]:
    if not parsed.host_percent_encoded:
        return []
    return [
        _f(
            "PG-HOST-003",
            "Percent-encoded hostname",
            Severity.HIGH,
            "Characters in the hostname are hidden using percent-encoding. A browser decodes them "
            "and visits the site shown below.",
            [f"Decoded host: {parsed.host_unicode}"],
            VERIFY_INDEPENDENTLY,
            "deception",
        )
    ]


@rule(
    "PG-HOST-004",
    "Mixed alphabets in the domain name",
    "deception",
    rationale="Mixing scripts (e.g. Latin with Cyrillic or Greek) in one label is the basis of "
    "homograph attacks such as 'аpple.com' with a Cyrillic 'а'.",
    limitations="Some legitimate multilingual brands mix Latin with another script. Latin+CJK is not flagged.",
)
def _mixed_script(parsed: ParsedURL, features: URLFeatures) -> list[Finding]:
    return [
        _f(
            "PG-HOST-004",
            "Mixed alphabets in the domain name",
            Severity.HIGH,
            "Part of the domain name mixes letters from different alphabets. Such names can look "
            "identical to a well-known domain while being a completely different site.",
            [f"Label '{label}' uses scripts: {', '.join(scripts)}", f"ASCII (punycode) form: {parsed.host_ascii}"],
            VERIFY_INDEPENDENTLY,
            "deception",
        )
        for label, scripts in features.mixed_script_labels
    ]


@rule(
    "PG-HOST-005",
    "Internationalised domain name",
    "host",
    rationale="Internationalised domain names are legitimate and widely used, but they are shown "
    "here with their punycode form so look-alikes can be spotted.",
    limitations="Informational on its own.",
)
def _idn(parsed: ParsedURL, features: URLFeatures) -> list[Finding]:
    if not parsed.is_idn or features.mixed_script_labels or features.lookalikes:
        return []
    return [
        _f(
            "PG-HOST-005",
            "Internationalised domain name",
            Severity.LOW,
            "The domain uses non-ASCII characters. This is normal for many languages; compare the "
            "punycode form with the site you expect.",
            [f"Displayed: {parsed.host_unicode}", f"Punycode: {parsed.host_ascii}"],
            category="host",
        )
    ]


@rule(
    "PG-HOST-006",
    "Characters not permitted by current domain standards",
    "host",
    rationale="IDNA 2008 forbids symbols such as emoji and some compatibility characters in domain "
    "names. Hostnames that only pass the older, looser rules are unusual.",
    limitations="A few legacy domains registered under IDNA 2003 rules remain in use.",
)
def _idna_lenient(parsed: ParsedURL, features: URLFeatures) -> list[Finding]:
    if parsed.idna_strict_valid:
        return []
    return [
        _f(
            "PG-HOST-006",
            "Characters not permitted by current domain standards",
            Severity.MEDIUM,
            "The domain name contains characters that current internationalised-domain rules do "
            "not allow. Such names are rare and can be used to imitate other domains.",
            [f"Punycode: {parsed.host_ascii}"],
            category="host",
        )
    ]


@rule(
    "PG-HOST-007",
    "Excessive subdomain depth",
    "host",
    rationale="Phishing links often stack subdomains ('secure.login.account.example.net') so the "
    "beginning of the hostname looks trustworthy.",
    limitations="CDNs and cloud services legitimately use deep hostnames.",
)
def _deep_subdomains(parsed: ParsedURL, features: URLFeatures) -> list[Finding]:
    depth = int(features.numeric["num_subdomains"])
    if depth < 4:
        return []
    severity = Severity.MEDIUM if depth >= 6 else Severity.LOW
    return [
        _f(
            "PG-HOST-007",
            "Excessive subdomain depth",
            severity,
            "The hostname has many subdomain levels. Only the registered domain at the end "
            "identifies who controls the site.",
            [f"Subdomain levels: {depth}", f"Registered domain: {parsed.registrable_domain}"],
            category="host",
        )
    ]


@rule(
    "PG-HOST-008",
    "Many hyphens in the registered domain",
    "host",
    rationale="Hyphen-heavy domains ('secure-account-update-service.example') are typical of "
    "throwaway phishing registrations.",
    limitations="Plenty of legitimate small-business domains contain hyphens.",
)
def _hyphens(parsed: ParsedURL, features: URLFeatures) -> list[Finding]:
    count = int(features.numeric["num_hyphens_registrable"])
    if count < 3:
        return []
    return [
        _f(
            "PG-HOST-008",
            "Many hyphens in the registered domain",
            Severity.LOW,
            "The registered domain contains several hyphens, a pattern common in disposable phishing domains.",
            [f"Registered domain: {parsed.registrable_domain}"],
            category="host",
        )
    ]


@rule(
    "PG-HOST-009",
    "Top-level domain with elevated abuse rates",
    "host",
    rationale="Some low-cost or free top-level domains are over-represented in abuse reports.",
    limitations="Most sites on these TLDs are legitimate. Low severity and never decisive alone.",
)
def _abuse_tld(parsed: ParsedURL, features: URLFeatures) -> list[Finding]:
    if not features.numeric["elevated_abuse_tld"]:
        return []
    return [
        _f(
            "PG-HOST-009",
            "Top-level domain with elevated abuse rates",
            Severity.LOW,
            "The domain ends in a top-level domain that appears disproportionately often in abuse "
            "reports. This alone says little about this particular site.",
            [f"TLD: .{features.tld}"],
            category="host",
        )
    ]


@rule(
    "PG-HOST-010",
    "Free hosting or tunnelling platform",
    "host",
    rationale="Free hosting and tunnelling services let anyone publish a page within minutes and "
    "are frequently used for short-lived phishing pages.",
    limitations="These platforms also host many legitimate projects.",
)
def _free_hosting(parsed: ParsedURL, features: URLFeatures) -> list[Finding]:
    if not features.free_hosting_suffix:
        return []
    impersonating = bool(features.brand_mentions or features.keywords_host or features.keywords_path)
    if impersonating:
        return [
            _f(
                "PG-HOST-010",
                "Brand or login page on a free hosting platform",
                Severity.MEDIUM,
                "The page is hosted on a platform where anyone can publish content, and its address "
                "refers to a brand or to signing in. Real organisations do not host their login "
                "pages on free platforms.",
                [f"Platform: {features.free_hosting_suffix}", f"Site: {parsed.registrable_domain}"],
                VERIFY_INDEPENDENTLY,
                "host",
            )
        ]
    return [
        _f(
            "PG-HOST-010",
            "Free hosting or tunnelling platform",
            Severity.LOW,
            "The page is hosted on a platform where anyone can publish content. The platform's "
            "reputation says nothing about who created this specific page.",
            [f"Platform: {features.free_hosting_suffix}", f"Site: {parsed.registrable_domain}"],
            category="host",
        )
    ]


@rule(
    "PG-HOST-011",
    "Link shortener hides the destination",
    "host",
    rationale="Shortened links conceal the final destination. PhishGuard deliberately does not "
    "follow links (to avoid contacting attacker infrastructure), so the target is unknown.",
    limitations="Shorteners are widely used legitimately.",
)
def _shortener(parsed: ParsedURL, features: URLFeatures) -> list[Finding]:
    if not features.shortener:
        return []
    return [
        _f(
            "PG-HOST-011",
            "Link shortener hides the destination",
            Severity.LOW,
            "This is a shortened link, so the real destination cannot be seen. PhishGuard does not "
            "open links, so it has not checked where this one leads.",
            [f"Shortener: {features.shortener}"],
            "Use the shortener's preview feature or ask the sender for the full address.",
            "host",
        )
    ]


@rule(
    "PG-HOST-012",
    "Local or reserved network address",
    "host",
    rationale="Addresses such as localhost or 192.168.x.x refer to the visitor's own network, not a public website.",
    limitations="Informational.",
)
def _private(parsed: ParsedURL, features: URLFeatures) -> list[Finding]:
    if not features.numeric["is_private_address"]:
        return []
    return [
        _f(
            "PG-HOST-012",
            "Local or reserved network address",
            Severity.INFO,
            "The link points to a device on a local or reserved network (for example your router "
            "or your own computer). A link like this in an email or message is unusual.",
            [f"Host: {parsed.host_ascii}"],
            category="host",
        )
    ]


@rule(
    "PG-HOST-013",
    "Non-standard port",
    "host",
    rationale="Public websites normally use ports 80/443. Other ports suggest ad-hoc servers.",
    limitations="Development servers and some admin panels legitimately use other ports.",
)
def _port(parsed: ParsedURL, features: URLFeatures) -> list[Finding]:
    if not parsed.nonstandard_port:
        return []
    return [
        _f(
            "PG-HOST-013",
            "Non-standard port",
            Severity.LOW,
            "The link specifies an unusual network port. This is common for test servers and rare "
            "for public sites that ask for personal information.",
            [f"Port: {parsed.port}"],
            category="host",
        )
    ]


# ---------------------------------------------------------------------------
# Brand impersonation
# ---------------------------------------------------------------------------


@rule(
    "PG-BRAND-001",
    "Brand name used as a subdomain of an unrelated site",
    "brand",
    rationale="'paypal.com.account-check.example' is controlled by account-check.example. Putting a "
    "brand in the subdomain is one of the most common impersonation techniques.",
    limitations="Only brands in the built-in list are recognised. Partner sites occasionally use "
    "a brand name in a subdomain legitimately.",
)
def _brand_subdomain(parsed: ParsedURL, features: URLFeatures) -> list[Finding]:
    mentions = [m for m in features.brand_mentions if m.location == "subdomain"]
    seen: set[str] = set()
    out = []
    spoofed = features.official_domain_in_subdomain
    if spoofed:
        brand = next((b for b in BRANDS if spoofed in b.official_domains), None)
        name = brand.name if brand else spoofed
        if brand:
            seen.add(brand.token)
        out.append(
            _f(
                "PG-BRAND-001",
                f"Official {name} domain placed in front of another domain",
                Severity.CRITICAL,
                f"The hostname begins with '{spoofed}', but everything before the final registered domain "
                f"is chosen freely by its owner. This site belongs to '{parsed.registrable_domain}', not {name}.",
                [f"Hostname: {parsed.host_unicode}", f"Actual registered domain: {parsed.registrable_domain}"],
                VERIFY_INDEPENDENTLY,
                "brand",
            )
        )
    for m in mentions:
        if m.brand in seen:
            continue
        seen.add(m.brand)
        out.append(
            _f(
                "PG-BRAND-001",
                f"{m.brand_name} name used on an unrelated domain",
                Severity.HIGH,
                f"The hostname starts with '{m.evidence}', suggesting {m.brand_name}, but the site is "
                f"actually controlled by '{parsed.registrable_domain}', which is not an official "
                f"{m.brand_name} domain.",
                [f"Subdomain: {m.evidence}", f"Registered domain: {parsed.registrable_domain}"],
                VERIFY_INDEPENDENTLY,
                "brand",
            )
        )
    return out


@rule(
    "PG-BRAND-002",
    "Brand name inside an unofficial domain",
    "brand",
    rationale="Domains such as 'paypal-secure-login.example' are registered by third parties to "
    "borrow a brand's credibility.",
    limitations="Brand fan sites, resellers and defensive registrations not in the official list "
    "are also flagged. An exact brand name on another TLD is rated lower.",
)
def _brand_registrable(parsed: ParsedURL, features: URLFeatures) -> list[Finding]:
    out = []
    for m in features.brand_mentions:
        if m.location != "registrable":
            continue
        exact = parsed.registrable_label == m.brand
        severity = Severity.MEDIUM if exact else Severity.HIGH
        explanation = (
            f"'{parsed.registrable_domain}' uses the {m.brand_name} name but is not one of its known "
            "official domains. Organisations sometimes own other domains, so verify independently."
            if exact
            else f"'{parsed.registrable_domain}' combines the {m.brand_name} name with other words. Such "
            f"domains are usually registered by third parties, not by {m.brand_name}."
        )
        out.append(
            _f(
                "PG-BRAND-002",
                f"{m.brand_name} name inside an unofficial domain",
                severity,
                explanation,
                [f"Registered domain: {parsed.registrable_domain}"],
                VERIFY_INDEPENDENTLY,
                "brand",
            )
        )
    return out


@rule(
    "PG-BRAND-003",
    "Look-alike of a well-known brand",
    "brand",
    rationale="Typosquats ('paypa1', 'rnicrosoft') and homoglyphs (Cyrillic letters that look Latin) "
    "imitate trusted domains character by character.",
    limitations="Edit-distance matching can flag ordinary words close to a brand name; a small "
    "allow-list reduces this and such matches are rated medium.",
)
def _lookalike(parsed: ParsedURL, features: URLFeatures) -> list[Finding]:
    severity_by_method = {
        "homoglyph": Severity.CRITICAL,
        "ascii-substitution": Severity.HIGH,
        "edit-distance": Severity.MEDIUM,
    }

    def severity_for(m: LookalikeMatch) -> Severity:
        # A whole registered domain spelled to imitate a brand ("paypa1.com")
        # is near-unambiguous; a matching fragment inside a longer name less so.
        if m.method == "ascii-substitution" and m.whole_domain:
            return Severity.CRITICAL
        return severity_by_method[m.method]

    description = {
        "homoglyph": "uses characters from another alphabet that look identical to",
        "ascii-substitution": "swaps look-alike characters (such as 1 for l or rn for m) to imitate",
        "edit-distance": "differs by a single character from",
    }
    return [
        _f(
            "PG-BRAND-003",
            f"Look-alike of {m.brand_name}",
            severity_for(m),
            f"The domain part '{m.label}' {description[m.method]} '{m.brand}', but this is not an "
            f"official {m.brand_name} domain.",
            [
                f"Domain label: {m.label}",
                f"Imitates: {m.brand}",
                f"Technique: {m.method}",
                f"Punycode host: {parsed.host_ascii}",
            ],
            VERIFY_INDEPENDENTLY,
            "brand",
        )
        for m in features.lookalikes
    ]


@rule(
    "PG-BRAND-004",
    "Brand referenced in the path of an unrelated site",
    "brand",
    rationale="Phishing pages are often placed at paths like '/paypal.com/login' on compromised "
    "sites so the URL contains a familiar name.",
    limitations="News, reviews and help articles mention brands in their paths legitimately, so a "
    "bare mention is low severity.",
)
def _brand_path(parsed: ParsedURL, features: URLFeatures) -> list[Finding]:
    if features.official_domain_in_path:
        severity = Severity.HIGH if features.keywords_path else Severity.MEDIUM
        return [
            _f(
                "PG-BRAND-004",
                "Official domain name embedded in the path",
                severity,
                f"The address contains '{features.official_domain_in_path}' after the hostname, but "
                f"the page is hosted on '{parsed.registrable_domain or parsed.host_ascii}'. This "
                "makes the link look official without being so.",
                [
                    f"Embedded name: {features.official_domain_in_path}",
                    f"Actual site: {parsed.registrable_domain or parsed.host_ascii}",
                ],
                VERIFY_INDEPENDENTLY,
                "brand",
            )
        ]
    mentions = [m for m in features.brand_mentions if m.location == "path"]
    if not mentions:
        return []
    names = sorted({m.brand_name for m in mentions})
    if features.keywords_path:
        return [
            _f(
                "PG-BRAND-004",
                "Brand name with login wording on an unrelated site",
                Severity.MEDIUM,
                "The path combines a well-known brand name with login, verification or payment "
                "wording, but the site is not one of the brand's official domains.",
                [f"Brand(s): {', '.join(names)}", f"Words: {', '.join(features.keywords_path[:6])}"],
                VERIFY_INDEPENDENTLY,
                "brand",
            )
        ]
    return [
        _f(
            "PG-BRAND-004",
            "Brand mentioned in the path of an unrelated site",
            Severity.LOW,
            "The path mentions a well-known brand although the site is not one of its official "
            "domains. This is common in news articles and only matters alongside other signs.",
            [f"Brand(s): {', '.join(names)}"],
            category="brand",
        )
    ]


# ---------------------------------------------------------------------------
# Wording, transport, path
# ---------------------------------------------------------------------------


@rule(
    "PG-KW-001",
    "Account or security wording in the hostname",
    "wording",
    rationale="Hostnames like 'verify-account.example' or 'secure-login.example.net' try to sound "
    "official to prompt credential entry.",
    limitations="Many legitimate services use 'login.' or 'account.' subdomains; official brand domains are excluded.",
)
def _kw_host(parsed: ParsedURL, features: URLFeatures) -> list[Finding]:
    if not features.keywords_host:
        return []
    return [
        _f(
            "PG-KW-001",
            "Account or security wording in the hostname",
            Severity.MEDIUM,
            "The hostname contains words associated with logins, payments or account security. "
            "Attackers use such words so a link sounds official.",
            [f"Words: {', '.join(features.keywords_host)}"],
            category="wording",
        )
    ]


@rule(
    "PG-KW-002",
    "Account or security wording in the path",
    "wording",
    rationale="Credential-related words in the path are weak signals often seen in phishing kits.",
    limitations="Extremely common on legitimate login pages; low severity.",
)
def _kw_path(parsed: ParsedURL, features: URLFeatures) -> list[Finding]:
    if not features.keywords_path or features.official_brands:
        return []
    return [
        _f(
            "PG-KW-002",
            "Account or security wording in the path",
            Severity.LOW,
            "The path or query mentions logins, verification or payments. This is normal for real "
            "login pages and only relevant alongside other warning signs.",
            [f"Words: {', '.join(features.keywords_path[:8])}"],
            category="wording",
        )
    ]


@rule(
    "PG-TLS-001",
    "Unencrypted connection",
    "transport",
    rationale="Plain HTTP exposes anything typed into the page. HTTP alone is not evidence of "
    "phishing (and HTTPS is not evidence of safety), so it is only weighted when the link "
    "also suggests a login or payment.",
    limitations="Many harmless informational sites still use HTTP.",
)
def _http(parsed: ParsedURL, features: URLFeatures) -> list[Finding]:
    if parsed.scheme != "http":
        return []
    credential_context = bool(features.keywords_host or features.keywords_path)
    if credential_context and not features.numeric["is_private_address"]:
        return [
            _f(
                "PG-TLS-001",
                "Login or payment wording over an unencrypted connection",
                Severity.MEDIUM,
                "The link uses plain HTTP and appears to lead to a login, verification or payment "
                "page. Anything entered there could be intercepted, and legitimate services use HTTPS "
                "for such pages.",
                ["Scheme: http"],
                VERIFY_INDEPENDENTLY,
                "transport",
            )
        ]
    return [
        _f(
            "PG-TLS-001",
            "Unencrypted connection (HTTP)",
            Severity.INFO,
            "The link uses plain HTTP. This is not a phishing indicator by itself, but do not enter "
            "personal information on unencrypted pages.",
            ["Scheme: http"],
            category="transport",
        )
    ]


@rule(
    "PG-PATH-001",
    "Unusual percent-encoding",
    "encoding",
    rationale="Double encoding (%25xx) or heavy encoding is used to slip past filters and hide "
    "keywords or nested URLs.",
    limitations="Some tracking and search URLs are heavily encoded legitimately.",
)
def _encoding(parsed: ParsedURL, features: URLFeatures) -> list[Finding]:
    out = []
    if features.numeric["has_double_encoding"]:
        out.append(
            _f(
                "PG-PATH-001",
                "Double percent-encoding",
                Severity.MEDIUM,
                "Parts of the link are encoded twice, a technique used to hide content from security filters.",
                ["Pattern: %25XX"],
                category="encoding",
            )
        )
    elif features.numeric["num_percent_encodings"] > 15:
        out.append(
            _f(
                "PG-PATH-001",
                "Heavy percent-encoding",
                Severity.LOW,
                "The path or query contains many encoded characters, which makes it harder to "
                "read what the link contains.",
                [f"Encoded sequences: {int(features.numeric['num_percent_encodings'])}"],
                category="encoding",
            )
        )
    return out


@rule(
    "PG-PATH-002",
    "Embedded redirect to another address",
    "structure",
    rationale="Open-redirect parameters (?url=https://...) let attackers route victims through a "
    "trusted domain to a malicious one.",
    limitations="Sign-in flows (OAuth redirect_uri) and link trackers use this pattern legitimately.",
)
def _redirect(parsed: ParsedURL, features: URLFeatures) -> list[Finding]:
    if not features.redirect_params:
        return []
    return [
        _f(
            "PG-PATH-002",
            "Embedded redirect to another address",
            Severity.LOW,
            "The link carries another web address in its parameters. Sites use this to forward "
            "visitors, and attackers abuse it to bounce through trusted domains.",
            [f"Parameter(s): {', '.join(features.redirect_params)}"],
            category="structure",
        )
    ]


@rule(
    "PG-PATH-003",
    "Direct link to an executable or archive",
    "payload",
    rationale="Links that download executables, scripts or installers are a primary malware delivery route.",
    limitations="Software vendors legitimately link to installers.",
)
def _download(parsed: ParsedURL, features: URLFeatures) -> list[Finding]:
    ext = features.file_extension
    if not ext:
        return []
    is_exec = bool(features.numeric["has_executable_extension"])
    return [
        _f(
            "PG-PATH-003",
            "Direct link to an executable file" if is_exec else "Direct link to an archive",
            Severity.MEDIUM if is_exec else Severity.LOW,
            "The link appears to download a file that could run code on your device."
            if is_exec
            else "The link appears to download a compressed archive, which can contain executable files.",
            [f"File extension: .{ext}"],
            "Only install software obtained from the vendor's official website or app store.",
            "payload",
        )
    ]


@rule(
    "PG-PATH-004",
    "Path tricks (backslashes or dot segments)",
    "structure",
    rationale="Backslashes and '..' segments are rewritten by browsers and can make a link display "
    "differently from where it leads.",
    limitations="Occasionally produced by buggy but harmless software.",
)
def _path_tricks(parsed: ParsedURL, features: URLFeatures) -> list[Finding]:
    evidence = []
    if parsed.backslash_in_path:
        evidence.append("Backslash in path")
    if features.numeric["has_dot_segments"]:
        evidence.append("'.' or '..' path segments")
    if not evidence:
        return []
    return [
        _f(
            "PG-PATH-004",
            "Path tricks (backslashes or dot segments)",
            Severity.LOW,
            "The path contains characters that browsers rewrite before visiting the page.",
            evidence,
            category="structure",
        )
    ]


def rule_catalogue() -> list[dict[str, str]]:
    """Metadata for every registered rule (used by the methodology page)."""
    return [
        {
            "rule_id": r.rule_id,
            "title": r.title,
            "category": r.category,
            "rationale": r.rationale,
            "limitations": r.limitations,
        }
        for r in sorted(RULES, key=lambda r: r.rule_id)
    ]
