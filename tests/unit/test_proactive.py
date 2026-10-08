"""Checagens próprias viram Finding (fonte 'scanner') válido no contrato."""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema

from scanner.common.models import Outcome, Status, Validation
from scanner.validation.proactive import CHECKS, build_finding


def _validation(name: str, outcome: Outcome) -> Validation:
    from datetime import UTC, datetime

    return Validation(validator=name, outcome=outcome, reason="x", validated_at=datetime.now(UTC))


def test_build_finding_is_contract_valid_and_scanner_sourced() -> None:
    schema = json.loads((Path(__file__).parents[2] / "contracts/finding.schema.json").read_text())
    v = _validation("broken_access_control", Outcome.CONFIRMED)
    f = build_finding("scan-1", "t-1", "http://juice-shop:3000/rest/basket/1", v)
    jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker()).validate(
        f.model_dump(mode="json")
    )
    assert f.source.tool == "scanner"
    assert f.owasp == "A01:2025" and f.status is Status.CONFIRMED
    assert f.schema_version == "1.1"


def test_every_proactive_validator_has_metadata() -> None:
    for name in (
        "broken_access_control",
        "exposed_sensitive_file",
        "weak_authentication",
        "jwt_integrity",
        "logging_monitoring",
    ):
        assert name in CHECKS and CHECKS[name].owasp.startswith("A")


# --- orquestrador A04 (ligado no pipeline): roda os caminhos e emite achados ---------------

from types import SimpleNamespace  # noqa: E402

from scanner.common.models import Scope  # noqa: E402
from scanner.validation.exposed_files import SENSITIVE_PATHS  # noqa: E402
from scanner.validation.proactive import run_exposed_files  # noqa: E402
from tests.conftest import resp  # noqa: E402


class FakeProbe:
    def __init__(self, exposed: set[str]) -> None:
        self.guard = SimpleNamespace(allows=lambda u: True)
        self.exposed = exposed
        self.requested: list[str] = []

    def request(self, method: str, url: str):
        self.requested.append(url)
        if any(p in url for p in self.exposed):
            return resp("conteudo confidencial de verdade e bem longo", status=200)
        return resp("", status=404)


def _scope() -> Scope:
    return Scope(
        scope_id="s",
        verified=True,
        locked=True,
        base_urls=["http://juice-shop:3000/"],
        allowed_hosts=["juice-shop"],
    )


def test_run_exposed_files_emits_for_exposed_only() -> None:
    client = FakeProbe(exposed={SENSITIVE_PATHS[0]})
    fs = run_exposed_files(_scope(), client, "scan-1", "t-1")
    assert len(fs) == 1
    assert fs[0].source.tool == "scanner"
    assert fs[0].owasp == "A04:2025"
    assert SENSITIVE_PATHS[0] in fs[0].location.url
    assert len(client.requested) == len(SENSITIVE_PATHS)  # sondou todos os caminhos


def test_run_exposed_files_empty_when_all_protected() -> None:
    assert run_exposed_files(_scope(), FakeProbe(exposed=set()), "scan-1", "t-1") == []
