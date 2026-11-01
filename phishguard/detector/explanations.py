"""User-facing wording for verdicts, recommendations and limitations.

Kept separate from the decision logic so wording can change without touching
the verdict precedence, and so templates and the API use identical text.
"""

from __future__ import annotations

from enum import StrEnum


class Verdict(StrEnum):
    CONFIRMED_MALICIOUS = "confirmed_malicious"
    HIGH_RISK = "high_risk"
    SUSPICIOUS = "suspicious"
    NO_THREAT_DETECTED = "no_threat_detected"
    INCONCLUSIVE = "inconclusive"


VERDICT_INFO: dict[Verdict, dict[str, str]] = {
    Verdict.CONFIRMED_MALICIOUS: {
        "label": "Confirmed malicious",
        "icon": "octagon-alert",
        "summary": "A threat-intelligence service explicitly lists this URL as malicious.",
    },
    Verdict.HIGH_RISK: {
        "label": "High risk",
        "icon": "triangle-alert",
        "summary": "Strong indicators of deception were found in this address.",
    },
    Verdict.SUSPICIOUS: {
        "label": "Suspicious",
        "icon": "circle-alert",
        "summary": "Some meaningful warning signs were found in this address.",
    },
    Verdict.NO_THREAT_DETECTED: {
        "label": "No threat detected",
        "icon": "circle-check",
        "summary": "The available checks found no significant warning signs. This is not a "
        "guarantee that the site is safe.",
    },
    Verdict.INCONCLUSIVE: {
        "label": "Inconclusive",
        "icon": "circle-help",
        "summary": "There was not enough reliable information to reach a conclusion.",
    },
}

RECOMMENDATIONS: dict[Verdict, list[str]] = {
    Verdict.CONFIRMED_MALICIOUS: [
        "Do not open this link.",
        "If you already entered a password, change it immediately from the official site or app "
        "and enable two-factor authentication.",
        "If you entered payment details, contact your bank or card issuer.",
        "Report the message that contained the link to your email provider or IT team.",
    ],
    Verdict.HIGH_RISK: [
        "Do not open this link or enter any information on the page.",
        "Reach the organisation by typing its official address yourself or using its app.",
        "If you have already entered credentials, change them and enable two-factor authentication.",
    ],
    Verdict.SUSPICIOUS: [
        "Avoid entering passwords, codes or payment details through this link.",
        "Verify the sender through a separate, trusted channel.",
        "Visit the organisation's site by typing its address yourself.",
    ],
    Verdict.NO_THREAT_DETECTED: [
        "Still check that the domain is exactly the one you expect before signing in.",
        "Be cautious with unexpected messages that create urgency, even if the link looks normal.",
    ],
    Verdict.INCONCLUSIVE: [
        "Treat the link with caution until it can be checked again.",
        "Try the scan again later, or verify the site through a trusted channel.",
    ],
}

GENERAL_LIMITATIONS = [
    "PhishGuard analyses the address only. It never opens the page, so page content, redirects "
    "and downloads are not inspected.",
    "Newly created phishing sites often appear before any blocklist includes them, and "
    "legitimate sites can be compromised.",
]


def verdict_label(value: str) -> str:
    try:
        return VERDICT_INFO[Verdict(value)]["label"]
    except ValueError:
        return value
