"""Sanitize email HTML for safe embedded preview in the report"""
import re


def sanitize_html_for_preview(html: str) -> str:
    """
    Return HTML stripped of dangerous elements/attributes so it can be embedded
    in an iframe srcdoc for visual analyst review without external loads or script execution.
    """
    if not html:
        return ""

    html = re.sub(r'<script\b[^>]*>.*?</script>', '', html, flags=re.IGNORECASE | re.DOTALL)
    html = re.sub(r'<script\b[^>]*/?>', '', html, flags=re.IGNORECASE)

    html = re.sub(r'<iframe\b[^>]*>.*?</iframe>', '', html, flags=re.IGNORECASE | re.DOTALL)
    html = re.sub(r'<iframe\b[^>]*/?>', '', html, flags=re.IGNORECASE)

    html = re.sub(r'<object\b[^>]*>.*?</object>', '', html, flags=re.IGNORECASE | re.DOTALL)
    html = re.sub(r'<embed\b[^>]*/?>', '', html, flags=re.IGNORECASE)

    html = re.sub(r'<link\b[^>]*/?>', '', html, flags=re.IGNORECASE)

    html = re.sub(r'<meta\b[^>]*http-equiv\b[^>]*/?>', '', html, flags=re.IGNORECASE)

    html = re.sub(r'\son\w+\s*=\s*"[^"]*"', '', html, flags=re.IGNORECASE)
    html = re.sub(r"\son\w+\s*=\s*'[^']*'", '', html, flags=re.IGNORECASE)
    html = re.sub(r'\son\w+\s*=\s*[^\s>]+', '', html, flags=re.IGNORECASE)

    html = re.sub(r'href\s*=\s*"javascript:[^"]*"', 'href="#blocked-js"', html, flags=re.IGNORECASE)
    html = re.sub(r"href\s*=\s*'javascript:[^']*'", "href='#blocked-js'", html, flags=re.IGNORECASE)

    html = re.sub(
        r'(<img\b[^>]*\ssrc\s*=\s*)(["\'])([^"\']+)\2',
        r'\1\2#blocked-image\2',
        html,
        flags=re.IGNORECASE,
    )

    html = re.sub(
        r'(<a\b[^>]*\shref\s*=\s*)(["\'])(https?://[^"\']+)\2',
        r'\1\2#external-link-blocked\2 data-original-href=\2\3\2',
        html,
        flags=re.IGNORECASE,
    )

    banner = '''<div style="background:#fef3c7;border:2px solid #d97706;padding:12px 16px;margin-bottom:16px;font-family:system-ui,sans-serif;font-size:12px;color:#78350f;border-radius:6px;"><strong>atarus-phishcheck preview:</strong> scripts removed, external resources blocked, all links disabled. Links show their real destination via data-original-href.</div>'''

    return banner + html


def has_renderable_html(html: str) -> bool:
    if not html:
        return False
    stripped = re.sub(r'<[^>]+>', '', html).strip()
    return len(stripped) > 20 or ('<img' in html.lower() or '<table' in html.lower())
