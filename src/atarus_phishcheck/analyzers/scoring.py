"""Aggregate findings into a phishing likelihood score"""
from atarus_phishcheck.models import AnalysisResult


SEVERITY_WEIGHTS = {
    "high": 25,
    "medium": 10,
    "low": 3,
    "info": 0,
}


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
        result.verdict = "clean"
