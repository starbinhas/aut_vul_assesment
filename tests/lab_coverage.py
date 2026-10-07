"""Mede a cobertura do nosso scanner contra o Juice Shop.

Não ataca nada: lê os achados que o nosso scan já gravou no banco e cruza com a lista de
vulnerabilidades que o próprio Juice Shop publica em `/api/Challenges` (a app descreve as
próprias falhas, por categoria). O resultado é uma tabela por categoria do OWASP Top 10: quantas
debilidades o alvo tem, em quantas o nosso scan produziu achado, e quantas foram confirmadas.

É o que torna "cobrir todas as debilidades" verificável: sem medir, não dá para dizer o que falta.

    docker compose -f docker-compose.yml -f docker-compose.lab.yml --profile test \
        run --rm tests python -m tests.lab_coverage <scan_id>
"""

from __future__ import annotations

import os
import sys
from collections import defaultdict
from dataclasses import dataclass, field

import httpx
from sqlalchemy import select

from scanner.common.config import get_settings
from scanner.common.db import FindingRow, make_session_factory
from scanner.common.models import Finding, Status
from scanner.common.owasp import CATEGORIES, owasp_for_cwe
from scanner.validation.coverage_map import plan_for

# Categorias do Juice Shop (campo `category` de /api/Challenges) → OWASP Top 10:2025.
# A app usa rótulos próprios; mapeamos para falar a mesma língua do nosso relatório.
JUICE_CATEGORY_TO_OWASP: dict[str, str] = {
    "Broken Access Control": "A01:2025",
    "Improper Input Validation": "A01:2025",
    "Security Misconfiguration": "A02:2025",
    "Vulnerable Components": "A03:2025",
    "Cryptographic Issues": "A04:2025",
    "Injection": "A05:2025",
    "XSS": "A05:2025",
    "XXE": "A05:2025",
    "Unvalidated Redirects": "A01:2025",
    "Broken Authentication": "A07:2025",
    "Insecure Deserialization": "A08:2025",
    "Broken Anti Automation": "A09:2025",
    "Sensitive Data Exposure": "A04:2025",
    "Security through Obscurity": "A02:2025",
    "Miscellaneous": None,  # sem mapeamento direto: fica fora da conta por categoria
}

CONFIRMED = {Status.CONFIRMED, Status.LIKELY}


@dataclass
class CategoryCoverage:
    owasp: str
    name: str
    target_weaknesses: int = 0  # desafios do Juice Shop nesta categoria
    our_findings: int = 0  # achados nossos (abertos) nesta categoria
    our_confirmed: int = 0  # destes, confirmados/prováveis por prova determinística
    unmapped_target: list[str] = field(default_factory=list)


def _target_weaknesses(base_url: str) -> dict[str, int] | None:
    """Conta os desafios do Juice Shop por categoria OWASP. None se o alvo não respondeu."""
    try:
        resp = httpx.get(f"{base_url.rstrip('/')}/api/Challenges", timeout=15)
        resp.raise_for_status()
        data = resp.json().get("data", [])
    except (httpx.HTTPError, ValueError) as exc:
        print(f"aviso: não foi possível ler /api/Challenges ({exc}); medindo só o nosso lado.")
        return None
    counts: dict[str, int] = defaultdict(int)
    unknown: set[str] = set()
    for ch in data:
        category = ch.get("category", "")
        if category not in JUICE_CATEGORY_TO_OWASP:
            unknown.add(category)
            continue
        owasp = JUICE_CATEGORY_TO_OWASP[category]
        if owasp is not None:
            counts[owasp] += 1
    if unknown:
        print(f"aviso: categorias do Juice Shop sem mapeamento: {sorted(unknown)}")
    return dict(counts)


def _our_findings(scan_id: str) -> list[Finding]:
    sessions = make_session_factory(get_settings().database_url)
    with sessions() as session:
        rows = session.scalars(select(FindingRow).where(FindingRow.scan_id == scan_id)).all()
        findings = [Finding.model_validate(r.data) for r in rows]
    if not findings:
        sys.exit(f"nenhum achado para {scan_id} (o scan terminou? rodou a validação?)")
    return findings


def _owasp_of(f: Finding) -> str | None:
    return f.owasp or owasp_for_cwe(f.cwe)


def measure(scan_id: str) -> list[CategoryCoverage]:
    base_url = os.environ.get("LAB_JUICE_SHOP_URL", "http://juice-shop:3000")
    target_counts = _target_weaknesses(base_url)
    findings = _our_findings(scan_id)

    cov = {code: CategoryCoverage(owasp=code, name=name) for code, name in CATEGORIES.items()}
    if target_counts:
        for code, n in target_counts.items():
            cov[code].target_weaknesses = n
    for f in findings:
        code = _owasp_of(f)
        if code is None or f.status not in {Status.CONFIRMED, Status.LIKELY, Status.UNCONFIRMED}:
            continue
        cov[code].our_findings += 1
        if f.status in CONFIRMED:
            cov[code].our_confirmed += 1
    return [cov[code] for code in sorted(cov)]


def _print(rows: list[CategoryCoverage], scan_id: str) -> None:
    has_target = any(r.target_weaknesses for r in rows)
    print(f"\nCobertura do scan {scan_id} (OWASP Top 10:2025)\n")
    header = f"{'Categoria':<42}{'Alvo':>6}{'Achados':>9}{'Conf.':>7}  {'Estado':<10}"
    print(header)
    print("-" * len(header))
    touched_target = 0
    categories_with_target = 0
    for r in rows:
        if r.target_weaknesses:
            categories_with_target += 1
            if r.our_findings:
                touched_target += 1
        alvo = str(r.target_weaknesses) if r.target_weaknesses else "·"
        plan = plan_for(r.owasp)
        estado = plan.status if plan else ""
        print(
            f"{r.owasp} {r.name:<36}{alvo:>6}{r.our_findings:>9}{r.our_confirmed:>7}  {estado:<10}"
        )
    print("-" * len(header))
    if has_target:
        print(
            f"\nCategorias do alvo com ao menos um achado nosso: "
            f"{touched_target}/{categories_with_target}"
        )
    print(
        "Achados: abertos (confirmados + prováveis + não confirmados). "
        "Conf.: confirmados/prováveis por prova determinística."
    )
    from scanner.validation.coverage_map import missing

    pend = missing()
    if pend:
        print("\nAinda nosso e não pronto:")
        for pl in pend:
            print(f"  {pl.owasp} [{pl.status}] {pl.detector} — {pl.note}")


def coverage(scan_id: str) -> None:
    _print(measure(scan_id), scan_id)


def main() -> None:
    if len(sys.argv) != 2:
        sys.exit("uso: python -m tests.lab_coverage <scan_id>")
    coverage(sys.argv[1])


if __name__ == "__main__":
    main()
