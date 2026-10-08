"""Comparação entre scans, agrupamento de variantes e nomes em pt-BR (interface)."""

from __future__ import annotations

from scanner.common.grouping import group_key, normalize_key
from scanner.common.models import Finding, Status
from scanner.report.builder import build_report
from scanner.report.catalog import static_remediation
from scanner.report.models import Report
from scanner.report.names import display_title
from scanner.web import labels
from scanner.web.services import compare
from tests.conftest import LAB_URL, make_finding


def _report(*findings: Finding) -> Report:
    validated = [f.model_copy(update={"status": Status.UNCONFIRMED}) for f in findings]
    return build_report(
        "scan-1", "target-1", validated, lambda f: (static_remediation(f), "catalog")
    )


def _sqli(url: str = LAB_URL + "/rest/products/search?q=x") -> Finding:
    return make_finding(rule_id="40018", cwe=89, title="SQL Injection", url=url)


def _csp(url: str = LAB_URL + "/") -> Finding:
    return make_finding(
        rule_id="10038",
        cwe=693,
        param=None,
        url=url,
        title="Content Security Policy (CSP) Header Not Set",
    )


def test_absence_on_untested_page_is_not_a_fix() -> None:
    before = _report(_sqli(), _csp())
    now = _report(_csp())  # o scan novo não chegou à página da busca
    c = compare(now, before)
    assert c is not None
    assert [i.finding.title for i in c.not_retested] == ["SQL Injection"]
    assert c.gone == []


def test_absence_on_retested_page_is_gone() -> None:
    page = LAB_URL + "/rest/products/search?q=x"
    before = _report(_sqli(page), _csp(page))
    now = _report(_csp(page))  # mesma página testada de novo, sem a injeção
    c = compare(now, before)
    assert c is not None
    assert [i.finding.title for i in c.gone] == ["SQL Injection"]
    assert c.not_retested == []
    assert len(c.persisting) == 1


def test_coverage_drop_is_flagged() -> None:
    r = _report(_csp())
    c = compare(r, r, pages_now=153, pages_before=242)
    assert c is not None and c.coverage_dropped
    c = compare(r, r, pages_now=230, pages_before=242)
    assert c is not None and not c.coverage_dropped
    c = compare(r, r)
    assert c is not None and not c.coverage_dropped


def test_http_method_variants_group_into_one_item() -> None:
    put = make_finding(rule_id="90028", cwe=None, title="Insecure HTTP Method - PUT", param=None)
    copy = make_finding(
        rule_id="90028",
        cwe=None,
        title="Insecure HTTP Method - COPY",
        param=None,
        url=LAB_URL + "/ftp",
    )
    assert group_key(put) == group_key(copy)
    assert len(_report(put, copy).items) == 1


def test_old_variant_keys_still_match_new_groups() -> None:
    assert (
        normalize_key("zap:90028|insecure http method - lock") == "zap:90028|insecure http method"
    )
    assert normalize_key("cwe:89|sql injection") == "cwe:89|sql injection"


def test_display_title_translates_and_falls_back() -> None:
    assert display_title("SQL Injection") == "Injeção de SQL"
    assert display_title("Insecure HTTP Method - MKCOL") == "Métodos HTTP perigosos habilitados"
    assert display_title("Some Brand New Rule") == "Some Brand New Rule"


def test_verify_command_detection() -> None:
    assert labels.is_command("curl -sI https://SEU-SITE/ | grep -i set-cookie")
    assert not labels.is_command("Envie o valor 1' no parâmetro do achado.")


def test_operator_notes_are_hidden_from_clients() -> None:
    assert labels.public_phase("active") == "Testes ativos"
    assert labels.public_phase("cancelado: alvo caiu (máquina dormiu)") == ""


def test_legacy_validation_reasons_are_rewritten() -> None:
    assert labels.reason("ainda não há validador para esta família").startswith("Ainda não temos")
    assert labels.reason("SQLITE_ERROR refletido") == "SQLITE_ERROR refletido"
