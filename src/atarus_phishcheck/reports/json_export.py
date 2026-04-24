import os
import json
from dataclasses import asdict
from atarus_phishcheck.models import AnalysisResult


def generate(result: AnalysisResult, output_path: str) -> str:
    data = {
        "tool": "atarus-phishcheck",
        "version": "0.1.0",
        "analyzed_at": result.analyzed_at,
        "source_file": result.source_file,
        "verdict": result.verdict,
        "phish_score": result.phish_score,
        "headers": {
            "from": result.headers.from_header,
            "from_email": result.headers.from_email,
            "from_domain": result.headers.from_domain,
            "reply_to": result.headers.reply_to,
            "return_path": result.headers.return_path,
            "to": result.headers.to,
            "subject": result.headers.subject,
            "date": result.headers.date,
            "message_id": result.headers.message_id,
            "x_mailer": result.headers.x_mailer,
            "x_originating_ip": result.headers.x_originating_ip,
            "received_count": len(result.headers.received_chain),
        },
        "authentication": {
            "spf_result": result.auth.spf_result,
            "spf_record": result.auth.spf_record,
            "dkim_result": result.auth.dkim_result,
            "dmarc_result": result.auth.dmarc_result,
            "dmarc_record": result.auth.dmarc_record,
            "dmarc_policy": result.auth.dmarc_policy,
        },
        "indicators": [
            {"type": i.type, "value": i.value, "context": i.context, "reputation": i.reputation}
            for i in result.indicators
        ],
        "findings": [
            {
                "category": f.category,
                "severity": f.severity,
                "title": f.title,
                "description": f.description,
                "recommendation": f.recommendation,
                "evidence": f.evidence,
            }
            for f in result.findings
        ],
        "severity_counts": result.severity_counts,
    }

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(data, f, indent=2)
    return output_path
