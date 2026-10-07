import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from scanner.common.authz import UnauthorizedScanError, check_authorized
from scanner.common.db import Base, Scan
from scanner.common.models import StageMessage


@pytest.fixture
def session():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as s:
        yield s


def msg(scope) -> StageMessage:
    return StageMessage(
        message_id="m",
        scan_id="scan-1",
        target_id="target-1",
        stage="web.requested",
        scope=scope,
        payload={},
    )


def add_scan(session, scope, **kw) -> None:
    data = {
        "scan_id": "scan-1",
        "target_id": "target-1",
        "verified": True,
        "scope_locked": True,
        "scope": scope.model_dump(mode="json"),
    } | kw
    session.add(Scan(**data))
    session.flush()


def test_authorized(session, scope) -> None:
    add_scan(session, scope)
    assert check_authorized(session, msg(scope)) == scope


def test_unknown_scan_is_refused(session, scope) -> None:
    with pytest.raises(UnauthorizedScanError):
        check_authorized(session, msg(scope))


def test_unverified_target_is_refused(session, scope) -> None:
    add_scan(session, scope, verified=False)
    with pytest.raises(UnauthorizedScanError):
        check_authorized(session, msg(scope))


def test_scope_tampering_is_refused(session, scope) -> None:
    add_scan(session, scope)
    tampered = scope.model_copy(update={"allowed_hosts": ["juice-shop", "other.example"]})
    with pytest.raises(UnauthorizedScanError):
        check_authorized(session, msg(tampered))
