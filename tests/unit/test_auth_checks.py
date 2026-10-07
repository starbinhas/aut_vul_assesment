"""Detecção de falha de autenticação (A07): ausência de bloqueio de login."""

from __future__ import annotations

from scanner.common.models import Outcome
from scanner.validation.auth_checks import classify_login_protection


def test_confirmed_when_no_lockout() -> None:
    v = classify_login_protection([401, 401, 401, 401, 401, 401])
    assert v.outcome is Outcome.CONFIRMED


def test_false_positive_when_rate_limited() -> None:
    for blocked in (429, 423):
        v = classify_login_protection([401, 401, 401, blocked])
        assert v.outcome is Outcome.FALSE_POSITIVE


def test_unconfirmed_when_too_few_attempts() -> None:
    v = classify_login_protection([401, 401])
    assert v.outcome is Outcome.UNCONFIRMED
