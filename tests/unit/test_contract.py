import json
from datetime import UTC, datetime
from pathlib import Path

import jsonschema
import pytest

from scanner.common.models import Outcome, Severity, StageMessage, Status, Validation
from tests.conftest import make_finding

CONTRACTS = Path(__file__).parents[2] / "contracts"


def load(name: str) -> dict:
    return json.loads((CONTRACTS / name).read_text())


def validator(name: str) -> jsonschema.Draft202012Validator:
    schema = load(name)
    return jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker())


def test_finding_model_matches_contract() -> None:
    f = make_finding(
        validation=Validation(
            validator="xss_reflected",
            outcome=Outcome.CONFIRMED,
            reason="x",
            validated_at=datetime.now(UTC),
        ),
        status=Status.CONFIRMED,
        owasp="A05:2025",
    )
    validator("finding.schema.json").validate(f.model_dump(mode="json"))


def test_enums_match_contract() -> None:
    schema = load("finding.schema.json")
    assert set(schema["properties"]["severity"]["enum"]) == {s.value for s in Severity}
    assert set(schema["properties"]["status"]["enum"]) == {s.value for s in Status}


def test_contract_rejects_unknown_status() -> None:
    data = make_finding().model_dump(mode="json") | {"status": "discarded_by_llm"}
    with pytest.raises(jsonschema.ValidationError):
        validator("finding.schema.json").validate(data)


def test_message_model_matches_contract(scope) -> None:
    msg = StageMessage(
        message_id="m1",
        scan_id="scan-1",
        target_id="target-1",
        stage="candidates",
        scope=scope,
        payload={"tool": "zap", "findings": []},
    )
    validator("message.schema.json").validate(msg.model_dump(mode="json"))
