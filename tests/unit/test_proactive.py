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
