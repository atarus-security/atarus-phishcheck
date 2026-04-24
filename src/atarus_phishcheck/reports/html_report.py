import os
from jinja2 import Environment, FileSystemLoader, select_autoescape
from atarus_phishcheck.models import AnalysisResult


def generate(result: AnalysisResult, output_path: str) -> str:
    possible_dirs = [
        os.path.join(os.path.dirname(__file__), "..", "..", "..", "templates"),
        os.path.join(os.path.dirname(__file__), "..", "templates"),
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

    html_content = template.render(
        result=result,
        findings_by_category=findings_by_category,
        indicators_by_type=indicators_by_type,
    )

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w") as f:
        f.write(html_content)
    return output_path
