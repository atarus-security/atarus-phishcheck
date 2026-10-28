from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class Indicator:
    """Indicator of Compromise extracted from email"""
    type: str  # url, domain, ip, hash, email, file
    value: str
    context: str = ""  # where it was found
    reputation: str = "unknown"  # not_listed, suspicious, malicious, unknown


@dataclass
class Finding:
    """A single analysis finding"""
    category: str  # authentication, content, indicators, technical
    severity: str  # high, medium, low, info
    title: str
    description: str
    recommendation: str = ""
    evidence: str = ""


@dataclass
class AuthResult:
    """SPF/DKIM/DMARC results as read from the Authentication-Results header.

    'unknown' means no result was present in the headers. The tool never
    verifies a DKIM signature itself.
    """
    spf_result: str = "unknown"
    spf_record: str = ""
    dkim_result: str = "unknown"
    dkim_signature: str = ""
    dmarc_result: str = "unknown"
    dmarc_record: str = ""
    dmarc_policy: str = ""
    alignment_spf: bool = False
    alignment_dkim: bool = False
    records_looked_up: bool = False  # True only when the DNS lookups ran and answered


@dataclass
class EmailHeaders:
    """Parsed email headers"""
    raw: str = ""
    from_header: str = ""
    from_name: str = ""
    from_email: str = ""
    from_domain: str = ""
    reply_to: str = ""
    return_path: str = ""
    to: str = ""
    subject: str = ""
    date: str = ""
    message_id: str = ""
    received_chain: list = field(default_factory=list)
    x_mailer: str = ""
    x_originating_ip: str = ""
    authentication_results: str = ""
    dkim_signature: str = ""
    received_spf: str = ""


@dataclass
class EmailBody:
    """Parsed email body content"""
    text: str = ""
    html: str = ""
    urls: list = field(default_factory=list)
    attachments: list = field(default_factory=list)
    truncated: list = field(default_factory=list)  # notes about parts cut at the size cap


@dataclass
class CheckNotRun:
    """A check that did not run, or ran and did not complete, and why."""
    check: str
    reason: str


@dataclass
class AnalysisResult:
    """Complete analysis result"""
    analyzed_at: str = field(default_factory=lambda: datetime.now().isoformat())
    source_file: str = ""
    headers: EmailHeaders = None
    body: EmailBody = None
    auth: AuthResult = None
    indicators: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    phish_score: int = 0
    verdict: str = "unknown"  # no_strong_indicators, questionable, suspicious, likely_phishing
    mode: str = "offline"  # offline or online
    lookups_enabled: list = field(default_factory=list)
    checks_not_run: list = field(default_factory=list)  # list of CheckNotRun

    def add_finding(self, finding: Finding):
        self.findings.append(finding)

    def add_indicator(self, indicator: Indicator):
        existing = [i for i in self.indicators if i.type == indicator.type and i.value == indicator.value]
        if not existing:
            self.indicators.append(indicator)

    def note_not_run(self, check: str, reason: str):
        self.checks_not_run.append(CheckNotRun(check=check, reason=reason))

    @property
    def severity_counts(self) -> dict:
        counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.findings:
            sev = f.severity.lower()
            if sev in counts:
                counts[sev] += 1
        return counts
