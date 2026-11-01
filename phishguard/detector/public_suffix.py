"""Offline registrable-domain helper.

PhishGuard must never download data at scan time, so it cannot fetch the full
Public Suffix List (https://publicsuffix.org/) on demand. This module ships a
compact, curated subset covering the multi-label suffixes most often seen in
practice (country-code second-level domains and a few shared-hosting suffixes).

Any suffix not listed here is treated as a single-label suffix (``.com``,
``.org``, ``.in`` ...). This is a documented approximation: for an unlisted
multi-label suffix the "registrable domain" will be one label too short, which
can make a few rules slightly more or less sensitive. See
``docs/detection_methodology.md``.
"""

from __future__ import annotations

from dataclasses import dataclass

# Multi-label public suffixes. Keep entries lowercase, ASCII (punycode) form.
MULTI_LABEL_SUFFIXES: frozenset[str] = frozenset(
    {
        # United Kingdom
        "co.uk",
        "org.uk",
        "ac.uk",
        "gov.uk",
        "ltd.uk",
        "plc.uk",
        "me.uk",
        "net.uk",
        "nhs.uk",
        "sch.uk",
        # India
        "co.in",
        "net.in",
        "org.in",
        "firm.in",
        "gen.in",
        "ind.in",
        "ac.in",
        "edu.in",
        "res.in",
        "gov.in",
        "nic.in",
        "mil.in",
        "bank.in",
        "fin.in",
        # Australia / New Zealand
        "com.au",
        "net.au",
        "org.au",
        "edu.au",
        "gov.au",
        "asn.au",
        "id.au",
        "co.nz",
        "org.nz",
        "net.nz",
        "ac.nz",
        "govt.nz",
        # Asia
        "co.jp",
        "ne.jp",
        "or.jp",
        "ac.jp",
        "go.jp",
        "ad.jp",
        "com.cn",
        "net.cn",
        "org.cn",
        "gov.cn",
        "edu.cn",
        "com.hk",
        "org.hk",
        "edu.hk",
        "gov.hk",
        "com.sg",
        "edu.sg",
        "gov.sg",
        "org.sg",
        "net.sg",
        "com.my",
        "org.my",
        "gov.my",
        "edu.my",
        "co.kr",
        "or.kr",
        "go.kr",
        "ac.kr",
        "com.tw",
        "org.tw",
        "gov.tw",
        "edu.tw",
        "co.id",
        "or.id",
        "go.id",
        "ac.id",
        "web.id",
        "com.ph",
        "org.ph",
        "gov.ph",
        "co.th",
        "or.th",
        "go.th",
        "ac.th",
        "in.th",
        "com.vn",
        "gov.vn",
        "edu.vn",
        "com.pk",
        "org.pk",
        "gov.pk",
        "edu.pk",
        "com.bd",
        "gov.bd",
        "edu.bd",
        "com.lk",
        "gov.lk",
        "edu.lk",
        "com.np",
        "gov.np",
        "edu.np",
        # Middle East / Africa
        "co.il",
        "org.il",
        "ac.il",
        "gov.il",
        "com.sa",
        "gov.sa",
        "edu.sa",
        "ae.org",
        "gov.ae",
        "com.tr",
        "gov.tr",
        "edu.tr",
        "org.tr",
        "co.za",
        "org.za",
        "gov.za",
        "ac.za",
        "com.ng",
        "gov.ng",
        "edu.ng",
        "co.ke",
        "or.ke",
        "go.ke",
        "ac.ke",
        "com.eg",
        "gov.eg",
        "edu.eg",
        # Americas
        "com.br",
        "net.br",
        "org.br",
        "gov.br",
        "edu.br",
        "com.mx",
        "org.mx",
        "gob.mx",
        "edu.mx",
        "com.ar",
        "gob.ar",
        "org.ar",
        "edu.ar",
        "com.co",
        "gov.co",
        "edu.co",
        "com.pe",
        "gob.pe",
        "gc.ca",
        # Europe
        "com.pl",
        "net.pl",
        "org.pl",
        "gov.pl",
        "com.ua",
        "gov.ua",
        "org.ua",
        "co.at",
        "or.at",
        "gv.at",
        "com.es",
        "org.es",
        "gob.es",
        "com.gr",
        "gov.gr",
        "com.pt",
        "gov.pt",
        "com.ru",
        "org.ru",
        "net.ru",
        # Shared hosting / platform suffixes frequently abused for phishing.
        # Listing them makes each tenant its own registrable domain, which is
        # the correct trust boundary (tenant A is not tenant B).
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
        "cloudfront.net",
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


@dataclass(frozen=True)
class DomainParts:
    """Split of an ASCII hostname into suffix, registrable domain and subdomains."""

    public_suffix: str
    registrable_domain: str
    registrable_label: str
    subdomain_labels: tuple[str, ...]
    suffix_is_known_multilabel: bool


def split_domain(host_ascii: str) -> DomainParts:
    """Split ``host_ascii`` (lowercase, no trailing dot) into its parts.

    >>> split_domain("login.example.co.uk").registrable_domain
    'example.co.uk'
    """
    labels = [label for label in host_ascii.lower().split(".") if label]
    if not labels:
        return DomainParts("", "", "", (), False)
    if len(labels) == 1:
        return DomainParts("", labels[0], labels[0], (), False)

    # Longest-match on known multi-label suffixes (up to 3 labels).
    for size in (3, 2):
        if len(labels) > size:
            candidate = ".".join(labels[-size:])
            if candidate in MULTI_LABEL_SUFFIXES:
                registrable_label = labels[-size - 1]
                return DomainParts(
                    public_suffix=candidate,
                    registrable_domain=f"{registrable_label}.{candidate}",
                    registrable_label=registrable_label,
                    subdomain_labels=tuple(labels[: -size - 1]),
                    suffix_is_known_multilabel=True,
                )
        elif len(labels) == size and ".".join(labels) in MULTI_LABEL_SUFFIXES:
            # The host *is* a public suffix (e.g. "co.uk") - no registrable part.
            return DomainParts(".".join(labels), "", "", (), True)

    suffix = labels[-1]
    registrable_label = labels[-2]
    return DomainParts(
        public_suffix=suffix,
        registrable_domain=f"{registrable_label}.{suffix}",
        registrable_label=registrable_label,
        subdomain_labels=tuple(labels[:-2]),
        suffix_is_known_multilabel=False,
    )
