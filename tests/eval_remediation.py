"""Runner do eval de remediação (não é teste pytest; rode à mão).

    uv run python -m tests.eval_remediation

Pontua a remediação do CATÁLOGO ESTÁTICO para um conjunto representativo de achados, usando a
rubrica de concretude (`scanner/report/eval.py`). É o portão para mostrar a cliente e para trocar de
modelo: o catálogo é o piso (sempre aparece quando o LLM falha). Para comparar um modelo, gere a
remediação com o `Writer` e passe pela mesma `score_remediation`.
"""

from __future__ import annotations

from scanner.common.models import (
    Finding,
    Location,
    Severity,
    Source,
    Status,
    make_finding_id,
)
from scanner.report.catalog import static_remediation
from scanner.report.eval import score_remediation

# (rótulo, rule_id da ferramenta, cwe) — casos representativos por família de falha.
CASES: tuple[tuple[str, str, int | None], ...] = (
    ("XSS refletido", "40012", 79),
    ("SQL injection", "40018", 89),
    ("Clickjacking", "10020", 1021),
    ("Cookie sem flags", "10010", 614),
    ("Sem HSTS/TLS", "10035", 319),
    ("Arquivo exposto", "PITCHY-EF-01", 538),
    ("Listagem de diretório", "0", 548),
    ("Exposição de informação", "10037", 200),
    ("Sem validador/CWE", "99999", None),
)


def _finding(rule_id: str, cwe: int | None) -> Finding:
    tool = "scanner" if rule_id.startswith("PITCHY") else "zap"
    source = Source(tool=tool, rule_id=rule_id, rule_name=f"{tool} {rule_id}")  # type: ignore[arg-type]
    url = "http://example.test/x"
    return Finding(
        finding_id=make_finding_id("scan", source, "GET", url, None),
        scan_id="scan",
        target_id="t",
        source=source,
        title=rule_id,
        cwe=cwe,
        severity=Severity.MEDIUM,
        status=Status.CONFIRMED,
        location=Location(url=url, method="GET"),
        evidence=[],
    )


def main() -> int:
    print(f"{'caso':24} {'nota':>6} {'concreto':>9}")
    print("-" * 42)
    concrete = 0
    for label, rule_id, cwe in CASES:
        rem = static_remediation(_finding(rule_id, cwe))
        s = score_remediation(rem)
        concrete += s.is_concrete
        print(f"{label:24} {s.passed}/{s.total:>3} {('sim' if s.is_concrete else 'NÃO'):>9}")
    print("-" * 42)
    print(f"concretos: {concrete}/{len(CASES)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
