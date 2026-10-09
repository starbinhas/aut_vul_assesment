"""Benchmark de assertividade e constância do scanner (recall + regressão).

Mede o que o scanner PROVA (achados confirmados/prováveis por prova determinística) e compara com um
baseline gravado de uma execução boa conhecida. Serve a dois objetivos do produto:

- **Assertividade:** quantos tipos de falha provamos, por família OWASP (não "achados", mas provados).
- **Constância:** um portão de regressão — se uma falha que provávamos deixa de ser provada, o
  benchmark falha (saída != 0). É o que garante que uma mudança não baixa a qualidade em silêncio.

A pontuação (`report_from_findings`, `compare`) é PURA e testada em `tests/unit/test_benchmark.py`
(não precisa do laboratório). O `main` lê os achados de um scan real no banco e compara com o
baseline; roda contra o laboratório:

    # grava o baseline a partir de um scan bom conhecido (uma vez, contra o laboratório):
    docker compose ... run --rm tests python -m tests.benchmark <scan_id> --update
    # depois, no CI, compara e falha se houve regressão:
    docker compose ... run --rm tests python -m tests.benchmark <scan_id>

O baseline NÃO vem no repositório: é gerado da sua execução de laboratório (senão seria "móvel de
laboratório"). Sem baseline, o benchmark só reporta, sem portão.
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from scanner.common.models import Finding, Status
from scanner.common.owasp import owasp_for_cwe

PROVEN = {Status.CONFIRMED, Status.LIKELY}  # "provado" = passou por prova determinística
BASELINE_PATH = Path(__file__).parent / "fixtures" / "scan_baseline.json"


def _owasp_of(f: Finding) -> str:
    return f.owasp or owasp_for_cwe(f.cwe) or "sem-categoria"


def _signature(f: Finding) -> str:
    """Assinatura estável de uma prova: família OWASP + validador (ou regra da ferramenta).

    É o que o baseline rastreia: não a URL (que muda entre alvos), mas a CAPACIDADE provada.
    """
    detector = (f.validation.validator if f.validation else None) or f.source.rule_id or "?"
    return f"{_owasp_of(f)}:{detector}"


@dataclass(frozen=True)
class BenchmarkReport:
    proven_count: int
    by_family: dict[str, int]
    signatures: list[str]  # ordenado, deduplicado: as capacidades provadas neste scan

    def to_json(self) -> dict[str, object]:
        return {
            "proven_count": self.proven_count,
            "by_family": self.by_family,
            "signatures": self.signatures,
        }

    @classmethod
    def from_json(cls, data: dict[str, object]) -> BenchmarkReport:
        return cls(
            proven_count=int(data.get("proven_count", 0)),  # type: ignore[arg-type]
            by_family=dict(data.get("by_family", {})),  # type: ignore[arg-type]
            signatures=list(data.get("signatures", [])),  # type: ignore[arg-type]
        )


def report_from_findings(findings: list[Finding]) -> BenchmarkReport:
    """Resume as PROVAS (confirmados/prováveis) de um scan. Função pura."""
    proven = [f for f in findings if f.status in PROVEN]
    by_family = Counter(_owasp_of(f) for f in proven)
    signatures = sorted({_signature(f) for f in proven})
    return BenchmarkReport(
        proven_count=len(proven), by_family=dict(by_family), signatures=signatures
    )


@dataclass(frozen=True)
class Comparison:
    regressions: list[str]  # capacidades do baseline que SUMIRAM (falha o portão)
    additions: list[str]  # capacidades novas (bom; vira candidato a novo baseline)

    @property
    def ok(self) -> bool:
        return not self.regressions


def compare(current: BenchmarkReport, baseline: BenchmarkReport) -> Comparison:
    """Regressão = assinatura do baseline ausente agora. Função pura."""
    cur, base = set(current.signatures), set(baseline.signatures)
    return Comparison(
        regressions=sorted(base - cur),
        additions=sorted(cur - base),
    )


# --- E/S e execução (lado do laboratório) ------------------------------------------------


def load_baseline(path: Path = BASELINE_PATH) -> BenchmarkReport | None:
    if not path.exists():
        return None
    return BenchmarkReport.from_json(json.loads(path.read_text()))


def save_baseline(report: BenchmarkReport, path: Path = BASELINE_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report.to_json(), indent=2, ensure_ascii=False) + "\n")


def _findings_of(scan_id: str) -> list[Finding]:
    from sqlalchemy import select

    from scanner.common.config import get_settings
    from scanner.common.db import FindingRow, make_session_factory

    sessions = make_session_factory(get_settings().database_url)
    with sessions() as session:
        rows = session.scalars(select(FindingRow).where(FindingRow.scan_id == scan_id)).all()
    findings = [Finding.model_validate(r.data) for r in rows]
    if not findings:
        sys.exit(f"nenhum achado para {scan_id} (o scan terminou? rodou a validação?)")
    return findings


def _print(report: BenchmarkReport) -> None:
    print(f"\nProvas (confirmados/prováveis): {report.proven_count}")
    print("Por família OWASP:")
    for fam, n in sorted(report.by_family.items()):
        print(f"  {fam}: {n}")
    print(f"Capacidades provadas: {len(report.signatures)}")
    for sig in report.signatures:
        print(f"  • {sig}")


def main() -> None:
    args = sys.argv[1:]
    update = "--update" in args
    rest = [a for a in args if a != "--update"]
    if len(rest) != 1:
        sys.exit("uso: python -m tests.benchmark <scan_id> [--update]")
    report = report_from_findings(_findings_of(rest[0]))
    _print(report)
    if update:
        save_baseline(report)
        print(f"\nbaseline gravado em {BASELINE_PATH}")
        return
    baseline = load_baseline()
    if baseline is None:
        print("\n(sem baseline: rode com --update para gravar; sem portão de regressão por ora)")
        return
    cmp = compare(report, baseline)
    for sig in cmp.additions:
        print(f"[novo] provando agora: {sig}")
    for sig in cmp.regressions:
        print(f"[REGRESSÃO] deixou de provar: {sig}")
    if not cmp.ok:
        sys.exit(f"\nFALHA: {len(cmp.regressions)} regressão(ões) de capacidade de prova.")
    print("\nOK: nenhuma regressão de capacidade de prova.")


if __name__ == "__main__":
    main()
