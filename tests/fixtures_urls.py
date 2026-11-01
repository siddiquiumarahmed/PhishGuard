"""Synthetic URL fixtures.

All "malicious" examples use reserved names (RFC 2606 .example/.test,
example.com/net/org) or documentation IP ranges (RFC 5737), so tests never
reference live attacker infrastructure. Benign examples are well-known
legitimate addresses that are only parsed, never visited.
"""

# Legitimate addresses that must NOT be rated suspicious or worse, including
# ones that trip superficial heuristics (long, http, login words, brand in path).
BENIGN_URLS = [
    "https://www.google.com/search?q=how+to+bake+bread&rlz=1C1GCEA_enIN&oq=how+to+bake&aqs=chrome.0.0i512l2j69i57"
    "j0i512l7.3456j0j7&sourceid=chrome&ie=UTF-8",
    "https://accounts.google.com/signin/v2/identifier?service=mail",
    "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=abc"
    "&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback",
    "https://github.com/pallets/flask",
    "https://en.wikipedia.org/wiki/Phishing",
    "https://www.amazon.in/gp/your-account/order-history",
    "https://www.onlinesbi.sbi/",
    "https://netbanking.hdfcbank.com/netbanking/",
    "https://www.irctc.co.in/nget/train-search",
    "http://example.com/",
    "https://news.example.org/2024/apple-earnings-report",
    "https://my-small-business.example.com/contact",
    "https://www.bbc.co.uk/news/technology-12345678",
    "https://docs.python.org/3/library/urllib.parse.html",
    "https://web.archive.org/web/2020/https://www.paypal.com/",
    "https://bücher.example/katalog",
    "http://localhost:5000/",
    "https://shop.example.net/cart?item=1234&qty=2&utm_source=newsletter&utm_medium=email&utm_campaign=autumn",
]

# (url, minimum expected verdict)
MALICIOUS_URLS = [
    ("https://paypal.com.account-verify.example.net/signin", "high_risk"),
    ("http://paypal.com@203.0.113.7/login", "high_risk"),
    ("https://xn--pypal-4ve.example/login", "high_risk"),
    ("https://secure-paypal-login.example.top/verify", "high_risk"),
    ("https://paypa1.example/signin", "high_risk"),
    ("https://rnicrosoft.example/", "high_risk"),
    ("https://xn--80ak6aa92e.example/", "high_risk"),
    ("https://sbi-kyc-update.example.xyz/onlinesbi/login.php", "high_risk"),
    ("https://binance-airdrop-claim.example.click/wallet/connect", "high_risk"),
    ("http://3232235777/admin", "suspicious"),
    ("https://evil.example/www.paypal.com/webscr?cmd=_login", "suspicious"),
    ("https://free-site.github.io/office365-login/", "suspicious"),
    ("http://198.51.100.23:8080/secure/bankofamerica/login.html", "suspicious"),
    ("http://%70aypal-login.example.net/", "suspicious"),
]

VERDICT_ORDER = ["no_threat_detected", "inconclusive", "suspicious", "high_risk", "confirmed_malicious"]


def at_least(verdict: str, minimum: str) -> bool:
    return VERDICT_ORDER.index(verdict) >= VERDICT_ORDER.index(minimum)
