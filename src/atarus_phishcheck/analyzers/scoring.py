"""Aggregate findings into a phishing likelihood score"""
from atarus_phishcheck.models import AnalysisResult


SEVERITY_WEIGHTS = {
    "high": 25,
    "medium": 10,
    "low": 3,
    "info": 0,
}

VERDICTS = ("no_strong_indicators", "questionable", "suspicious", "likely_phishing")

# The lowest band is a statement about what the checks that ran found, not
# about the email being genuine. The wording must never call an email
# legitimate, safe or clean; a test enforces that.
VERDICT_TEXT = {
    "no_strong_indicators": (
        "The checks that ran found no strong phishing indicators. This does not "
        "establish that the email is genuine: read the list of checks that did not "
        "run, and verify the sender through a channel you already trust before "
        "acting on anything it asks for."
    ),
    "questionable": (
        "Minor indicators were found. Look closer before interacting, and treat "
        "any request for credentials, payment or urgent action as unverified."
    ),
    "suspicious": (
        "Multiple suspicious indicators were found. Treat this email with caution "
        "and verify the sender through an independent channel."
    ),
    "likely_phishing": (
        "Strong phishing indicators were found. Do not click links, open "
        "attachments or respond. Report it to your security team."
    ),
    "unknown": "The email was not scored.",
}


def verdict_label(verdict: str) -> str:
    return verdict.replace("_", " ").upper()


def score_result(result: AnalysisResult) -> None:
    """Calculate phish score (0-100) and verdict. Modifies result in-place."""
    score = 0

    for f in result.findings:
        score += SEVERITY_WEIGHTS.get(f.severity, 0)

    high_count = sum(1 for f in result.findings if f.severity == "high")
    if high_count >= 3:
        score += 15
    elif high_count >= 2:
        score += 8

    auth_fails = sum(1 for f in result.findings if f.category == "authentication" and f.severity == "high")
    indicator_highs = sum(1 for f in result.findings if f.category == "indicators" and f.severity == "high")
    if auth_fails and indicator_highs:
        score += 15

    content_mediums = sum(1 for f in result.findings if f.category == "content" and f.severity in ("high", "medium"))
    if content_mediums >= 2 and (auth_fails or indicator_highs):
        score += 10

    score = min(score, 100)
    result.phish_score = score

    if score >= 75:
        result.verdict = "likely_phishing"
    elif score >= 40:
        result.verdict = "suspicious"
    elif score >= 15:
        result.verdict = "questionable"
    else:
        result.verdict = "no_strong_indicators"
