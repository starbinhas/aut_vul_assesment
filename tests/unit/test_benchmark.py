"""Scorer do benchmark (recall + regressão) — lógica pura, sem laboratório."""

from __future__ import annotations

from datetime import UTC, datetime

from scanner.common.models import Outcome, Status, Validation
from tests.benchmark import BenchmarkReport, compare, report_from_findings
from tests.conftest import make_finding


def _proven(validator: str, **kw):
    v = Validation(
        validator=validator,
        outcome=Outcome.CONFIRMED,
        reason="prova",
        validated_at=datetime.now(UTC),
    )
    return make_finding(status=Status.CONFIRMED, validation=v, **kw)


def test_report_counts_only_proven() -> None:
    findings = [
        _proven("xss_reflected", cwe=79),  # A05 (injeção, neste mapa)
        _proven("sqli_error", rule_id="40018", cwe=89, param="id"),  # A05
        make_finding(status=Status.UNCONFIRMED, cwe=79, param="z"),  # não provado -> fora
    ]
    report = report_from_findings(findings)
    assert report.proven_count == 2
    assert all(sig.count(":") >= 1 for sig in report.signatures)
    # a assinatura carrega o validador, não a URL
    assert any("xss_reflected" in s for s in report.signatures)


def test_signature_is_stable_across_urls() -> None:
    # Mesma capacidade (mesmo validador/família) em URLs diferentes = uma assinatura só.
    a = _proven("xss_reflected", cwe=79, url="http://juice-shop:3000/a?q=1")
    b = _proven("xss_reflected", cwe=79, url="http://juice-shop:3000/b?q=1")
    assert len(report_from_findings([a, b]).signatures) == 1


def test_compare_flags_regression_and_addition() -> None:
    baseline = BenchmarkReport(
        proven_count=2, by_family={}, signatures=["A05:2025:xss_reflected", "A05:2025:sqli_error"]
    )
    current = BenchmarkReport(
        proven_count=2,
        by_family={},
        signatures=["A05:2025:xss_reflected", "A01:2025:broken_access_control"],
    )
    cmp = compare(current, baseline)
    assert cmp.regressions == ["A05:2025:sqli_error"]  # sumiu -> regressão
    assert cmp.additions == ["A01:2025:broken_access_control"]  # novo -> bom
    assert cmp.ok is False  # há regressão -> portão falha


def test_compare_ok_when_no_regression() -> None:
    base = BenchmarkReport(proven_count=1, by_family={}, signatures=["A05:2025:xss_reflected"])
    cur = BenchmarkReport(
        proven_count=2,
        by_family={},
        signatures=["A05:2025:xss_reflected", "A04:2025:exposed_sensitive_file"],
    )
    assert compare(cur, base).ok is True


def test_report_json_roundtrip() -> None:
    report = report_from_findings([_proven("xss_reflected", cwe=79)])
    assert BenchmarkReport.from_json(report.to_json()) == report
