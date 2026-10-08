"""JSON → HTML (Jinja2, autoescape obrigatório: evidências contêm payloads) → PDF (WeasyPrint)."""

from __future__ import annotations

from typing import Any, NoReturn

from jinja2 import Environment, PackageLoader, select_autoescape

from scanner.report.models import Report
from scanner.report.names import client_reason, display_title, is_command

SEVERITY_PT = {
    "critical": "Crítica",
    "high": "Alta",
    "medium": "Média",
    "low": "Baixa",
    "info": "Informativa",
}
STATUS_PT = {
    "confirmed": "Confirmada",
    "likely": "Provável",
    "unconfirmed": "Não confirmada",
    "false_positive": "Falso positivo",
    "candidate": "Candidata",
}

_env = Environment(
    loader=PackageLoader("scanner.report", "templates"),
    autoescape=select_autoescape(default=True, default_for_string=True),
)
_env.filters["name"] = display_title
_env.filters["reason"] = client_reason
_env.tests["command"] = is_command
_env.filters["severity_pt"] = lambda s: SEVERITY_PT.get(str(s), str(s))
_env.filters["status_pt"] = lambda s: STATUS_PT.get(str(s), str(s))


def render_html(report: Report) -> str:
    return _env.get_template("report.html.j2").render(r=report)


def _no_fetch(url: str, *args: Any, **kwargs: Any) -> NoReturn:
    # O relatório é autocontido; nunca deixar o gerador de PDF acessar URLs (do cliente ou não).
    raise ValueError(f"recurso externo bloqueado: {url}")


def render_pdf(html: str) -> bytes:
    from weasyprint import HTML  # import tardio: depende de libs de sistema (pango)

    pdf: bytes = HTML(string=html, url_fetcher=_no_fetch).write_pdf()
    return pdf
