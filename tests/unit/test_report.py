from datetime import UTC, datetime
from types import SimpleNamespace

from scanner.common.models import Outcome, Severity, Status, Validation
from scanner.report.builder import build_report
from scanner.report.catalog import static_remediation
from scanner.report.llm import RemediationRequest, RemediationWriter, build_user_prompt
from scanner.report.render import render_html
from scanner.report.stack import detect_stack
from tests.conftest import make_finding


def _fp(f):
    v = Validation(
        validator="h",
        outcome=Outcome.FALSE_POSITIVE,
        reason="cabeçalho presente",
        validated_at=datetime.now(UTC),
    )
    return f.model_copy(update={"status": Status.FALSE_POSITIVE, "validation": v})


def test_report_separates_false_positives_and_keeps_unconfirmed() -> None:
    confirmed = make_finding(status=Status.CONFIRMED)
    unconfirmed = make_finding(param="other", status=Status.UNCONFIRMED)
    fp = _fp(make_finding(rule_id="10020", cwe=1021, param=None))
    report = build_report(
        "scan-1",
        "target-1",
        [unconfirmed, fp, confirmed],
        lambda f: (static_remediation(f), "catalog"),
    )
    # mesma falha (XSS) em dois parâmetros: um grupo, com o melhor status
    [item] = report.items
    assert item.status is Status.CONFIRMED and len(item.locations) == 2
    assert len(report.discarded) == 1
    assert report.summary.by_status["false_positive"] == 1


def test_every_item_has_remediation() -> None:
    f = make_finding(rule_id="99999", cwe=None, status=Status.UNCONFIRMED)
    report = build_report("scan-1", "target-1", [f], lambda f: (static_remediation(f), "catalog"))
    assert report.items[0].remediation.how_to_fix


def test_html_escapes_payloads() -> None:
    f = make_finding(status=Status.CONFIRMED, title="<script>alert(1)</script>")
    report = build_report("scan-1", "target-1", [f], lambda f: (static_remediation(f), "catalog"))
    html = render_html(report)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_html_summary_keeps_severity_order_and_client_names() -> None:
    f = make_finding(status=Status.CONFIRMED, title="SQL Injection", cwe=89, rule_id="40018")
    report = build_report("scan-1", "target-1", [f], lambda f: (static_remediation(f), "catalog"))
    # como volta do Postgres (JSONB): chaves em ordem qualquer
    shuffled = dict(reversed(list(report.summary.by_severity.items())))
    report = report.model_copy(
        update={"summary": report.summary.model_copy(update={"by_severity": shuffled})}
    )
    html = render_html(report)
    assert html.index("Crítica") < html.index("Alta") < html.index("Informativa")
    assert "Injeção de SQL" in html


def test_llm_prompt_has_no_client_data() -> None:
    f = make_finding(url="http://juice-shop:3000/conta?token=SEGREDO", param="token")
    prompt = build_user_prompt(RemediationRequest(f, "nginx", "pt-BR"))
    assert "juice-shop" not in prompt and "SEGREDO" not in prompt


class _FakeMessages:
    def __init__(self, response):
        self.response = response
        self.kwargs = None

    def parse(self, **kwargs):
        self.kwargs = kwargs
        return self.response


def test_refusal_returns_none_for_catalog_fallback() -> None:
    fake = _FakeMessages(
        SimpleNamespace(
            stop_reason="refusal",
            stop_details=SimpleNamespace(category="cyber"),
            parsed_output=None,
        )
    )
    writer = RemediationWriter(SimpleNamespace(messages=fake), "claude-opus-5-5", "high")
    assert writer.write(RemediationRequest(make_finding(), "generic", "pt-BR")) is None
    assert fake.kwargs["thinking"] == {"type": "adaptive"}
    assert fake.kwargs["output_config"] == {"effort": "high"}
    assert fake.kwargs["system"][0]["cache_control"] == {"type": "ephemeral"}


def test_detect_stack() -> None:
    assert detect_stack([make_finding()]) == "nginx"


def test_same_issue_on_many_pages_is_one_item() -> None:
    pages = [
        make_finding(
            rule_id="10021",
            cwe=693,
            param=None,
            title="X-Content-Type-Options Header Missing",
            url=f"http://juice-shop:3000/p{i}",
            status=Status.CONFIRMED,
        )
        for i in range(120)
    ]
    other = make_finding(status=Status.UNCONFIRMED)
    report = build_report(
        "scan-1", "target-1", [*pages, other], lambda f: (static_remediation(f), "catalog")
    )
    assert len(report.items) == 2
    header = next(i for i in report.items if i.finding.cwe == 693)
    assert len(header.locations) == 120
    assert report.summary.total_reported == 2
    assert report.summary.affected_pages == 121


# --- provedor LLM compatível com OpenAI (MVP gratuito: Groq etc.) ----------------------------

import json  # noqa: E402

from scanner.report.llm import OpenAICompatibleWriter  # noqa: E402


class _FakeCompletions:
    def __init__(self, content):
        self.content = content
        self.kwargs = None

    def create(self, **kwargs):
        self.kwargs = kwargs
        choice = SimpleNamespace(message=SimpleNamespace(content=self.content))
        return SimpleNamespace(choices=[choice])


def _fake_openai(content):
    comp = _FakeCompletions(content)
    client = SimpleNamespace(chat=SimpleNamespace(completions=comp))
    return client, comp


_VALID_REMEDIATION = json.dumps(
    {
        "what_it_is": "A entrada do usuário entra numa consulta SQL sem separação.",
        "why_it_matters": "Um atacante lê ou altera o banco inteiro.",
        "how_to_fix": [{"title": "Use consultas parametrizadas", "detail": "Nunca concatene."}],
        "how_to_verify": "Reenvie o payload e confirme que não há erro de SQL.",
        "references": ["https://cwe.mitre.org/data/definitions/89.html"],
    }
)


def test_compat_writer_parses_valid_json() -> None:
    client, comp = _fake_openai(_VALID_REMEDIATION)
    writer = OpenAICompatibleWriter(client, "llama-3.3-70b-versatile")
    out = writer.write(RemediationRequest(make_finding(), "nginx", "pt-BR"))
    assert out is not None and out.how_to_fix[0].title == "Use consultas parametrizadas"
    # JSON mode exigido (Groq precisa).
    assert comp.kwargs["response_format"] == {"type": "json_object"}


def test_compat_writer_masks_client_data() -> None:
    client, comp = _fake_openai(_VALID_REMEDIATION)
    writer = OpenAICompatibleWriter(client, "m")
    f = make_finding(url="http://juice-shop:3000/conta?token=SEGREDO", param="token")
    writer.write(RemediationRequest(f, "nginx", "pt-BR"))
    sent = json.dumps(comp.kwargs["messages"])
    assert "juice-shop" not in sent and "SEGREDO" not in sent


def test_compat_writer_returns_none_on_bad_json() -> None:
    client, _ = _fake_openai("isto não é json")
    writer = OpenAICompatibleWriter(client, "m")
    assert writer.write(RemediationRequest(make_finding(), "nginx", "pt-BR")) is None


def test_catalog_covers_info_disclosure_and_dir_listing() -> None:
    info = static_remediation(make_finding(tool="nuclei", rule_id="tech-detect", cwe=200))
    assert "passo a passo" not in info.how_to_fix[0].detail  # não é o texto genérico
    assert any("server" in (s.snippet or "").lower() for s in info.how_to_fix)
    listing = static_remediation(make_finding(tool="nuclei", rule_id="dir-listing", cwe=548))
    assert "autoindex" in " ".join(s.snippet or "" for s in listing.how_to_fix)


def test_report_items_sorted_severity_then_status() -> None:
    info = make_finding(tool="nuclei", rule_id="tech-detect", cwe=200, severity=Severity.INFO)
    sqli = make_finding(
        cwe=89, url="http://juice-shop:3000/busca?q=1", param="q", severity=Severity.HIGH
    )
    report = build_report("s", "t", [info, sqli], lambda f: (static_remediation(f), "catalog"))
    sevs = [i.severity.rank for i in report.items]
    assert sevs == sorted(sevs, reverse=True)  # da mais grave para a mais leve
