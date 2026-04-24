from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class Indicator:
    """Indicator of Compromise extracted from email"""
    type: str  # url, domain, ip, hash, email
    value: str
    context: str = ""  # where it was found
    reputation: str = "unknown"  # clean, suspicious, malicious, unknown


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
    """SPF/DKIM/DMARC check result"""
    spf_result: str = "none"
    spf_record: str = ""
    dkim_result: str = "none"
    dkim_signature: str = ""
    dmarc_result: str = "none"
    dmarc_record: str = ""
    dmarc_policy: str = ""
    alignment_spf: bool = False
    alignment_dkim: bool = False


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
    verdict: str = "unknown"  # clean, suspicious, likely_phishing, malicious

    def add_finding(self, finding: Finding):
        self.findings.append(finding)

    def add_indicator(self, indicator: Indicator):
        existing = [i for i in self.indicators if i.type == indicator.type and i.value == indicator.value]
        if not existing:
            self.indicators.append(indicator)

    @property
    def severity_counts(self) -> dict:
        counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.findings:
            sev = f.severity.lower()
            if sev in counts:
                counts[sev] += 1
        return counts
