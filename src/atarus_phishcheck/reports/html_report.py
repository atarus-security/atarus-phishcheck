import os
from jinja2 import Environment, FileSystemLoader, select_autoescape
from atarus_phishcheck import __version__
from atarus_phishcheck.analyzers import scoring
from atarus_phishcheck.models import AnalysisResult
from atarus_phishcheck.analyzers.sanitize import sanitize_html_for_preview, has_renderable_html


def generate(result: AnalysisResult, output_path: str) -> str:
    possible_dirs = [
        os.path.join(os.path.dirname(__file__), "..", "templates"),
        os.path.join(os.path.dirname(__file__), "..", "..", "..", "templates"),
    ]

    template_dir = None
    for d in possible_dirs:
        d = os.path.normpath(d)
        if os.path.isdir(d) and os.path.exists(os.path.join(d, "phishcheck_report.html")):
            template_dir = d
            break

    if template_dir is None:
        raise FileNotFoundError("Could not find templates/phishcheck_report.html")

    env = Environment(
        loader=FileSystemLoader(template_dir),
        autoescape=select_autoescape(default=True, default_for_string=True),
    )

    template = env.get_template("phishcheck_report.html")

    findings_by_category = {"authentication": [], "indicators": [], "content": [], "technical": []}
    for f in result.findings:
        cat = f.category
        if cat in findings_by_category:
            findings_by_category[cat].append(f)

    indicators_by_type = {}
    for i in result.indicators:
        indicators_by_type.setdefault(i.type, []).append(i)

    # The sanitizer returns a complete document; Jinja's autoescape encodes it
    # once for the srcdoc attribute. Escaping it here as well is what made the
    # preview show HTML source instead of a page.
    preview_html = ""
    preview_available = False
    if result.body and has_renderable_html(result.body.html):
        preview_html = sanitize_html_for_preview(result.body.html)
        preview_available = True

    html_content = template.render(
        result=result,
        version=__version__,
        verdict_label=scoring.verdict_label(result.verdict),
        verdict_text=scoring.VERDICT_TEXT.get(result.verdict, ""),
        findings_by_category=findings_by_category,
        indicators_by_type=indicators_by_type,
        preview_html=preview_html,
        preview_available=preview_available,
    )

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    return output_path
