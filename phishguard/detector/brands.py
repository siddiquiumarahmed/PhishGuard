"""Protected brands frequently impersonated in phishing, with their official domains.

This is deliberately a short, curated list. A brand is matched by its *token*
(the label people type, e.g. ``paypal``). A host is considered "official" for a
brand when its registrable domain is listed below (subdomains included).

Domains that host *user-controlled* content (github.io, sharepoint.com tenants,
googleusercontent.com, amazonaws.com, windows.net ...) are intentionally NOT
listed as official: anyone can publish there, so they must not suppress
impersonation findings.

Limitations (documented in docs/detection_methodology.md):
* Brands not listed are not protected by brand-impersonation rules.
* Some brands legitimately use domains not listed here (marketing, CDN,
  acquisitions). Such URLs may produce a brand-impersonation finding; the
  finding text tells the user to verify the domain independently.
* Very short tokens are excluded to avoid matching ordinary words.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Brand:
    token: str
    name: str
    official_domains: frozenset[str]
    # Short, distinctive alternative names. Matched only as a whole
    # hyphen-delimited hostname token (e.g. "sbi-kyc.example"), never inside
    # words or paths, because short tokens collide with ordinary text.
    aliases: frozenset[str] = frozenset()


def _b(token: str, name: str, *domains: str, aliases: tuple[str, ...] = ()) -> Brand:
    return Brand(token=token, name=name, official_domains=frozenset(domains), aliases=frozenset(aliases))


BRANDS: tuple[Brand, ...] = (
    _b("paypal", "PayPal", "paypal.com", "paypal.me", "paypalobjects.com", "paypal-community.com"),
    _b("apple", "Apple", "apple.com", "icloud.com", "apple.news", "me.com"),
    _b("icloud", "Apple iCloud", "icloud.com", "apple.com"),
    _b(
        "microsoft",
        "Microsoft",
        "microsoft.com",
        "live.com",
        "office.com",
        "microsoftonline.com",
        "outlook.com",
        "azure.com",
        "msn.com",
        "bing.com",
        "office365.com",
    ),
    _b("office365", "Microsoft 365", "office.com", "office365.com", "microsoft.com", "microsoftonline.com"),
    _b("outlook", "Microsoft Outlook", "outlook.com", "live.com", "office.com", "microsoft.com"),
    _b("onedrive", "Microsoft OneDrive", "onedrive.com", "live.com", "microsoft.com"),
    _b(
        "google",
        "Google",
        "google.com",
        "google.co.in",
        "google.co.uk",
        "gmail.com",
        "youtube.com",
        "goo.gl",
        "gstatic.com",
        "googleapis.com",
        "withgoogle.com",
        "g.co",
    ),
    _b("gmail", "Gmail", "gmail.com", "google.com"),
    _b(
        "amazon",
        "Amazon",
        "amazon.com",
        "amazon.in",
        "amazon.co.uk",
        "amazon.de",
        "amazon.fr",
        "amazon.ca",
        "amazon.co.jp",
        "amazon.com.au",
        "amazon.es",
        "amazon.it",
        "a2z.com",
        "primevideo.com",
    ),
    _b("netflix", "Netflix", "netflix.com", "nflxext.com", "nflximg.net"),
    _b("facebook", "Facebook", "facebook.com", "fb.com", "fb.me", "meta.com", "messenger.com"),
    _b("instagram", "Instagram", "instagram.com", "cdninstagram.com"),
    _b("whatsapp", "WhatsApp", "whatsapp.com", "whatsapp.net", "wa.me"),
    _b("linkedin", "LinkedIn", "linkedin.com", "lnkd.in"),
    _b("dropbox", "Dropbox", "dropbox.com", "db.tt"),
    _b("docusign", "DocuSign", "docusign.com", "docusign.net"),
    _b("adobe", "Adobe", "adobe.com", "adobelogin.com", "adobe.io"),
    _b("coinbase", "Coinbase", "coinbase.com"),
    _b("binance", "Binance", "binance.com"),
    _b("metamask", "MetaMask", "metamask.io"),
    _b("chase", "Chase", "chase.com", "jpmorganchase.com", "jpmorgan.com"),
    _b("wellsfargo", "Wells Fargo", "wellsfargo.com"),
    _b("bankofamerica", "Bank of America", "bankofamerica.com", "bofa.com", aliases=("bofa",)),
    _b("citibank", "Citibank", "citi.com", "citibank.com", "citibankonline.com"),
    _b("hsbc", "HSBC", "hsbc.com", "hsbc.co.uk", "hsbc.co.in"),
    _b("barclays", "Barclays", "barclays.co.uk", "barclays.com"),
    _b("onlinesbi", "State Bank of India", "onlinesbi.sbi", "sbi.co.in", "onlinesbi.com", "sbi", aliases=("sbi",)),
    _b("hdfcbank", "HDFC Bank", "hdfcbank.com", "hdfc.com", aliases=("hdfc",)),
    _b("icicibank", "ICICI Bank", "icicibank.com", "icici.bank.in", aliases=("icici",)),
    _b("axisbank", "Axis Bank", "axisbank.com"),
    _b("kotak", "Kotak Mahindra Bank", "kotak.com"),
    _b("paytm", "Paytm", "paytm.com", "paytm.in", "paytmbank.com"),
    _b("phonepe", "PhonePe", "phonepe.com"),
    _b("flipkart", "Flipkart", "flipkart.com"),
    _b("irctc", "IRCTC", "irctc.co.in"),
    _b("incometax", "Income Tax Department (India)", "incometax.gov.in", "incometaxindia.gov.in"),
    _b("steam", "Steam", "steampowered.com", "steamcommunity.com"),
    _b("steamcommunity", "Steam Community", "steamcommunity.com", "steampowered.com"),
    _b("roblox", "Roblox", "roblox.com"),
    _b("dhl", "DHL", "dhl.com", "dhl.de", "dhl.co.uk", "dhl.co.in"),
    _b("fedex", "FedEx", "fedex.com"),
    _b("usps", "USPS", "usps.com"),
    _b("ebay", "eBay", "ebay.com", "ebay.co.uk", "ebay.in", "ebay.de"),
    _b("yahoo", "Yahoo", "yahoo.com", "yahoo.co.jp", "yimg.com"),
    _b("twitter", "X / Twitter", "twitter.com", "x.com", "t.co"),
    _b("telegram", "Telegram", "telegram.org", "t.me", "telegram.me"),
    _b("discord", "Discord", "discord.com", "discord.gg", "discordapp.com", "discord.media"),
    _b("spotify", "Spotify", "spotify.com", "spoti.fi"),
    _b("github", "GitHub", "github.com"),
    _b("zoom", "Zoom", "zoom.us", "zoom.com"),
)

MIN_BRAND_TOKEN_LENGTH = 4

BRAND_BY_TOKEN: dict[str, Brand] = {b.token: b for b in BRANDS if len(b.token) >= MIN_BRAND_TOKEN_LENGTH}
BRAND_BY_ALIAS: dict[str, Brand] = {alias: b for b in BRANDS for alias in b.aliases}


def official_brands_for(registrable_domain: str, host: str) -> set[str]:
    """Return tokens of brands for which ``host`` is an official domain."""
    owned: set[str] = set()
    for brand in BRANDS:
        for domain in brand.official_domains:
            if registrable_domain == domain or host == domain or host.endswith("." + domain):
                owned.add(brand.token)
                break
    return owned
