# Detection methodology

PhishGuard analyses the **text of a URL**. It never opens, downloads or resolves the submitted address. Every scan runs up to three independent methods and then applies an explicit verdict precedence.

## 1. Parsing and validation (`detector/url_parser.py`)

The parser reads the address the way a browser does, so tricks that rely on parser differences are exposed rather than missed:

| Situation | Behaviour |
|---|---|
| Scheme other than `http`/`https` (`javascript:`, `data:`, `file:`, `ftp:`) | Rejected (`unsupported_scheme`) |
| Missing scheme (`example.com/login`) | Rejected with a hint (`missing_scheme`); the scheme is never guessed |
| Whitespace, control characters, bidi/zero-width characters | Rejected; invisible characters are called out as a deception technique |
| `user:password@host` | Accepted; the *last* `@` separates credentials from the host (as browsers do); the password is discarded immediately and kept out of `repr()` |
| Backslash before the path | Rejected (`backslash_in_authority`): browsers disagree on how to read it |
| Percent-encoded hostname (`%65xample.com`) | Decoded like a browser and flagged |
| Decimal / hex / octal / short IPv4 (`3232235777`, `0x7f.1`) | Converted with the WHATWG algorithm to the address a browser would contact and flagged as obfuscated |
| Out-of-range IPv4 (`999.1.1.1`), bad IPv6, zone IDs | Rejected |
| Unicode hostnames | Converted with UTS #46 / IDNA 2008; if that fails, the looser IDNA 2003 rules are tried so browser-reachable look-alikes are still analysed (and flagged) |
| Malformed punycode (`xn--zz`), empty labels, labels > 63 chars, host > 253 chars, numeric TLD | Rejected |
| Default port, trailing dot, upper-case host | Normalised and noted |

The **original** value is kept separately from the **normalised analysis form** (`scheme://host[:port]/path?query`, credentials and fragment removed, path and query *not* rewritten).

The registered domain is computed with an offline list of multi-label public suffixes (`detector/public_suffix.py`), including shared-hosting suffixes such as `github.io` or `pages.dev` so each tenant is treated as its own site. Unlisted multi-label suffixes are approximated as single-label suffixes.

## 2. Features (`detector/url_features.py`)

`extract_features()` produces a fixed, ordered vector of 47 numeric features (lengths, counts, ratios, flags) plus structured evidence used by the rules: brand mentions, look-alike matches, mixed-script labels, credential keywords, redirect parameters, file extensions, shorteners and free-hosting platforms. The **same function** builds the ML training matrix, so training and inference cannot drift apart. A hash of the feature names (`feature_set_version`) is stored with every model and checked at load time.

Brand impersonation uses a curated list (`detector/brands.py`) of frequently imitated organisations and their official domains. User-content platforms (`github.io`, `sharepoint.com` tenants, `amazonaws.com`, ...) are deliberately *not* treated as official.

Look-alikes are found by comparing a *skeleton* of each domain label with the brand token: confusable Cyrillic/Greek/Armenian letters, accents and ASCII substitutions (`0→o`, `1→l`, `rn→m`, `vv→w`) are mapped to a common form. Single-edit typos (Damerau-Levenshtein distance 1) are also checked for brand tokens of six or more characters, with an allow-list of ordinary words (`finance`, `cloud`, ...).

## 3. Rules (`detector/rule_engine.py`)

Each rule is a small function registered with its rationale and limitations; the methodology page in the application is generated from the same registry. A rule that raises an exception is recorded and isolated; it never crashes a scan.

Severities are categorical, not probabilities:

| Severity | Meaning |
|---|---|
| info | Context only; never affects the verdict |
| low | Weak signal, common on legitimate sites |
| medium | Meaningful warning sign |
| high | Strong indicator of deception |
| critical | Near-unambiguous deception technique |

| Rule | Title | Why it exists | Limitations |
|---|---|---|---|
| PG-BRAND-001 | Brand name used as a subdomain of an unrelated site | 'paypal.com.account-check.example' is controlled by account-check.example. Putting a brand in the subdomain is one of the most common impersonation techniques. | Only brands in the built-in list are recognised. Partner sites occasionally use a brand name in a subdomain legitimately. |
| PG-BRAND-002 | Brand name inside an unofficial domain | Domains such as 'paypal-secure-login.example' are registered by third parties to borrow a brand's credibility. | Brand fan sites, resellers and defensive registrations not in the official list are also flagged. An exact brand name on another TLD is rated lower. |
| PG-BRAND-003 | Look-alike of a well-known brand | Typosquats ('paypa1', 'rnicrosoft') and homoglyphs (Cyrillic letters that look Latin) imitate trusted domains character by character. | Edit-distance matching can flag ordinary words close to a brand name; a small allow-list reduces this and such matches are rated medium. |
| PG-BRAND-004 | Brand referenced in the path of an unrelated site | Phishing pages are often placed at paths like '/paypal.com/login' on compromised sites so the URL contains a familiar name. | News, reviews and help articles mention brands in their paths legitimately, so a bare mention is low severity. |
| PG-HOST-001 | Raw IP address instead of a domain name | Legitimate public services almost always use domain names. Raw IP addresses avoid domain registration and hide who operates the site. | Routers, development servers and some APIs are legitimately reached by IP. |
| PG-HOST-002 | Obfuscated IP address notation | Decimal, hexadecimal, octal or shortened IPv4 notation (e.g. http://3232235777/) is accepted by browsers but has no legitimate use in shared links; it exists to hide the destination. | None known for shared links. |
| PG-HOST-003 | Percent-encoded hostname | Browsers decode %XX sequences in hostnames, so encoding letters of a domain only serves to hide it from people and simple filters. | None known for shared links. |
| PG-HOST-004 | Mixed alphabets in the domain name | Mixing scripts (e.g. Latin with Cyrillic or Greek) in one label is the basis of homograph attacks such as 'аpple.com' with a Cyrillic 'а'. | Some legitimate multilingual brands mix Latin with another script. Latin+CJK is not flagged. |
| PG-HOST-005 | Internationalised domain name | Internationalised domain names are legitimate and widely used, but they are shown here with their punycode form so look-alikes can be spotted. | Informational on its own. |
| PG-HOST-006 | Characters not permitted by current domain standards | IDNA 2008 forbids symbols such as emoji and some compatibility characters in domain names. Hostnames that only pass the older, looser rules are unusual. | A few legacy domains registered under IDNA 2003 rules remain in use. |
| PG-HOST-007 | Excessive subdomain depth | Phishing links often stack subdomains ('secure.login.account.example.net') so the beginning of the hostname looks trustworthy. | CDNs and cloud services legitimately use deep hostnames. |
| PG-HOST-008 | Many hyphens in the registered domain | Hyphen-heavy domains ('secure-account-update-service.example') are typical of throwaway phishing registrations. | Plenty of legitimate small-business domains contain hyphens. |
| PG-HOST-009 | Top-level domain with elevated abuse rates | Some low-cost or free top-level domains are over-represented in abuse reports. | Most sites on these TLDs are legitimate. Low severity and never decisive alone. |
| PG-HOST-010 | Free hosting or tunnelling platform | Free hosting and tunnelling services let anyone publish a page within minutes and are frequently used for short-lived phishing pages. | These platforms also host many legitimate projects. |
| PG-HOST-011 | Link shortener hides the destination | Shortened links conceal the final destination. PhishGuard deliberately does not follow links (to avoid contacting attacker infrastructure), so the target is unknown. | Shorteners are widely used legitimately. |
| PG-HOST-012 | Local or reserved network address | Addresses such as localhost or 192.168.x.x refer to the visitor's own network, not a public website. | Informational. |
| PG-HOST-013 | Non-standard port | Public websites normally use ports 80/443. Other ports suggest ad-hoc servers. | Development servers and some admin panels legitimately use other ports. |
| PG-KW-001 | Account or security wording in the hostname | Hostnames like 'verify-account.example' or 'secure-login.example.net' try to sound official to prompt credential entry. | Many legitimate services use 'login.' or 'account.' subdomains; official brand domains are excluded. |
| PG-KW-002 | Account or security wording in the path | Credential-related words in the path are weak signals often seen in phishing kits. | Extremely common on legitimate login pages; low severity. |
| PG-LEN-001 | Unusually long URL | Very long links can hide the real hostname on small screens and are common in phishing kits that append tracking or victim identifiers. | Search results, analytics and single sign-on links are often long and legitimate. Low severity only. |
| PG-PATH-001 | Unusual percent-encoding | Double encoding (%25xx) or heavy encoding is used to slip past filters and hide keywords or nested URLs. | Some tracking and search URLs are heavily encoded legitimately. |
| PG-PATH-002 | Embedded redirect to another address | Open-redirect parameters (?url=https://...) let attackers route victims through a trusted domain to a malicious one. | Sign-in flows (OAuth redirect_uri) and link trackers use this pattern legitimately. |
| PG-PATH-003 | Direct link to an executable or archive | Links that download executables, scripts or installers are a primary malware delivery route. | Software vendors legitimately link to installers. |
| PG-PATH-004 | Path tricks (backslashes or dot segments) | Backslashes and '..' segments are rewritten by browsers and can make a link display differently from where it leads. | Occasionally produced by buggy but harmless software. |
| PG-TLS-001 | Unencrypted connection | Plain HTTP exposes anything typed into the page. HTTP alone is not evidence of phishing (and HTTPS is not evidence of safety), so it is only weighted when the link also suggests a login or payment. | Many harmless informational sites still use HTTP. |
| PG-URL-001 | Credentials embedded in the URL | Browsers ignore or warn about user:password@ prefixes; legitimate links almost never use them, but phishing links use them to push the real hostname out of view. | Some internal tools and FTP-era links still embed credentials; these will be flagged. |
| PG-URL-002 | Fake hostname placed before '@' | 'https://trusted.example@attacker.example/' visits attacker.example. Placing a domain name before '@' has no legitimate use and is a classic disguise. | Detection relies on the text before '@' looking like a domain name. |

### Deliberately weak signals

A long URL, plain HTTP, a "risky" TLD, a link shortener or a login keyword in the path are each **low** or **info** on their own. Plain HTTP only becomes medium when the address also suggests a login or payment. The regression suite (`tests/fixtures_urls.py`) contains legitimate URLs that trip these superficial heuristics (Google search URLs, OAuth redirects, `http://example.com/`, news articles that mention brands, archive.org copies of brand pages) and asserts they stay at *No threat detected*.

## 4. Threat intelligence

See [threat_intelligence.md](threat_intelligence.md). A provider result is one of: verified match, unverified listing, no match, not configured, or a failure (timeout, quota, credentials, malformed response, error). Failures are never treated as clean.

## 5. Machine learning

See [dataset_and_model.md](dataset_and_model.md). The model score is uncalibrated and shown as such. On its own it can raise a verdict to *Suspicious* at most, and it never lowers a rule-based verdict.

## 6. Verdict precedence (`detector/verdict_engine.py`)

The first matching step decides:

1. **Confirmed malicious**: a provider returned a verified match.
2. **High risk**: a critical finding; or two or more high findings; or one high finding corroborated by a medium finding, an ML score above threshold, or an unverified listing.
3. **Suspicious**: one high finding; or two or more medium findings; or an unverified listing; or an ML score above threshold.
4. **Inconclusive**: none of the above, but a necessary method did not complete: one or more rules failed, a *configured* provider failed, or `REQUIRE_REPUTATION_FOR_CLEAN=true` and no lookup completed.
5. **No threat detected**: otherwise. The response always lists which methods ran, and states that this is not a guarantee.

Design choices:

* A provider "not listed" result never lowers a verdict.
* An unconfigured provider is not a failure (the core scanner must work without credentials), but the result says plainly that no blocklist was consulted.
* A *configured* provider that fails makes an otherwise clean result **Inconclusive**, because a check the operator asked for is missing.

## 7. Heuristic risk index (`detector/scoring.py`)

`index = min(100, Σ weight(severity))` with weights info 0, low 5, medium 15, high 35, critical 60. It is labelled everywhere as a heuristic index; it is not a probability, has not been calibrated, and does not decide the verdict.

## 8. Known limitations

* Only the address is analysed: page content, certificates, redirects, WHOIS age and hosting reputation are not.
* Brand protection is limited to the built-in list; brands with legitimate domains missing from the list may produce false positives (findings say "verify independently").
* The suffix list is a curated subset of the Public Suffix List.
* Phishing on compromised legitimate sites with neutral paths, and brand-new domains with neutral names, can produce *No threat detected* unless a reputation service lists them.
* Shortened links are not expanded (that would contact the attacker's infrastructure).
