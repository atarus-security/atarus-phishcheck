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

    @property
    def dkim_shown(self) -> str:
        """The DKIM result as reports show it: a pass whose signing domain is
        not the sender's is marked, since anyone can sign with their own domain."""
        if self.dkim_result == "pass" and not self.alignment_dkim:
            return "pass (not aligned with From)"
        return self.dkim_result


@dataclass
class EmailHeaders:
    """Parsed email headers"""
    raw: str = ""
    from_header: str = ""
    from_name: str = ""
    from_email: str = ""
    from_domain: str = ""
    reply_to: str = ""
    reply_to_email: str = ""  # first address in Reply-To, parsed from the full raw value
    return_path: str = ""
    to: str = ""
    subject: str = ""
    date: str = ""
    message_id: str = ""
    received_chain: list = field(default_factory=list)  # the first 100 Received headers, top first
    received_count: int = 0  # how many Received headers the message has
    x_mailer: str = ""
    x_originating_ip: str = ""
    authentication_results: str = ""
    dkim_signature: str = ""
    received_spf: str = ""
    from_addresses: list = field(default_factory=list)  # every mailbox in the first From header
    from_header_count: int = 0  # how many From headers the message has
    header_count: int = 0  # headers the parser found at the top of the message
    from_more_mailboxes: bool = False  # the From header holds more mailboxes than were kept
    sender_candidates: list = field(default_factory=list)  # every domain a reader could take as the sender's
    malformed: list = field(default_factory=list)  # {header, reason, evidence, severity} for headers read leniently


@dataclass
class EmailBody:
    """Parsed email body content"""
    text: str = ""
    html: str = ""
    urls: list = field(default_factory=list)
    attachments: list = field(default_factory=list)
    truncated: list = field(default_factory=list)  # notes about parts cut at the size cap
    extra_html: list = field(default_factory=list)  # further HTML parts and HTML attachments, for the content checks
    extra_text: str = ""  # further text parts and text attachments, for the content checks
    part_problems: list = field(default_factory=list)  # malformed part headers other than file names
    urls_capped: bool = False  # more than MAX_URLS distinct links
    limited: str = ""  # why part of the message was not analysed, or ''
    read_digests: set = field(default_factory=set)  # digests of every text and HTML part read, so the raw scan does not repeat them
    raw_scan_text: list = field(default_factory=list)  # text and HTML found only by the raw scan of a message past the limits, for the brand check


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
    analysis_limited: str = ""  # why part of the message was not analysed, or ''

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
