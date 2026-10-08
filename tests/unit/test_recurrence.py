"""Etapa 7: quais alvos estão vencidos e o disparo do novo scan."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from scanner.common.db import Base, Organization, Scan, ScanStatus, Target
from scanner.common.queue import STREAM_RECON_REQUESTED
from scanner.recurrence.service import due_targets, is_due, run_once

NOW = datetime(2026, 10, 7, tzinfo=UTC)


def test_is_due_rules() -> None:
    assert is_due("manual", None, NOW) is False
    assert is_due("weekly", None, NOW) is True  # nunca escaneado, recorrência ligada
    assert is_due("weekly", NOW - timedelta(days=8), NOW) is True
    assert is_due("weekly", NOW - timedelta(days=3), NOW) is False
    assert is_due("monthly", NOW - timedelta(days=31), NOW) is True
    assert is_due("monthly", NOW - timedelta(days=10), NOW) is False


def _db():
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    return sessionmaker(engine, expire_on_commit=False)


def _target(sessions, tid, recurrence, verified=True):
    with sessions.begin() as s:
        if s.get(Organization, "org-a") is None:
            s.add(Organization(org_id="org-a", name="A"))
        s.add(
            Target(
                target_id=tid,
                org_id="org-a",
                domain=f"{tid}.com",
                base_url=f"https://{tid}.com/",
                verification_token="t",
                verified_at=NOW - timedelta(days=100) if verified else None,
                recurrence=recurrence,
            )
        )


def test_due_targets_filters_correctly() -> None:
    sessions = _db()
    _target(sessions, "weekly-old", "weekly")  # nunca escaneado -> vencido
    _target(sessions, "manual-site", "manual")  # manual -> nunca
    _target(sessions, "unverified", "weekly", verified=False)  # não verificado -> fora
    due = due_targets(_db_session(sessions), NOW)
    ids = {t.target_id for t in due}
    assert "weekly-old" in ids
    assert "manual-site" not in ids and "unverified" not in ids


def _db_session(sessions):
    return sessions()


def test_recent_scan_is_not_due_and_active_blocks() -> None:
    sessions = _db()
    _target(sessions, "weekly-recent", "weekly")
    _target(sessions, "weekly-active", "weekly")
    with sessions.begin() as s:
        s.add(
            Scan(
                scan_id="recent-1",
                target_id="weekly-recent",
                verified=True,
                scope_locked=True,
                scope={},
                status=ScanStatus.DONE,
                created_at=NOW - timedelta(days=2),  # recente -> não vencido
            )
        )
        s.add(
            Scan(
                scan_id="active-1",
                target_id="weekly-active",
                verified=True,
                scope_locked=True,
                scope={},
                status=ScanStatus.WEB_SCANNING,  # em andamento -> não dispara outro
                created_at=NOW - timedelta(days=30),
            )
        )
    ids = {t.target_id for t in due_targets(sessions(), NOW)}
    assert "weekly-recent" not in ids and "weekly-active" not in ids


def test_run_once_creates_scan_and_publishes_after_commit() -> None:
    sessions = _db()
    _target(sessions, "weekly-old", "weekly")
    published: list[tuple[str, object]] = []

    def publish(stream, msg):
        # no publish, o scan já tem de estar no banco (confirmado pelo worker-recon)
        with sessions() as chk:
            assert chk.get(Scan, msg.scan_id) is not None
        published.append((stream, msg))

    n = run_once(sessions, publish, NOW)
    assert n == 1
    [(stream, msg)] = published
    assert stream == STREAM_RECON_REQUESTED
    assert msg.stage == "recon.requested" and msg.payload == {"profile": "safe"}
    assert msg.scope.locked and msg.scope.allowed_hosts == ["weekly-old.com"]
