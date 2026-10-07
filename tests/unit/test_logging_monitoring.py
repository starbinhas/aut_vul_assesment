"""A09: checklist e teste de correlação de logs."""

from __future__ import annotations

from scanner.common.models import Outcome
from scanner.validation.logging_monitoring import CHECKLIST, classify_logging

MARKS = ["atk-aaa", "atk-bbb", "atk-ccc"]


def test_checklist_items_are_well_formed() -> None:
    ids = [i.id for i in CHECKLIST]
    assert len(ids) == len(set(ids)) and len(ids) >= 6
    assert all(i.question and i.why for i in CHECKLIST)


def test_confirmed_when_no_attack_is_logged() -> None:
    v = classify_logging(MARKS, "logs sem nada de interessante")
    assert v.outcome is Outcome.CONFIRMED


def test_false_positive_when_all_logged() -> None:
    v = classify_logging(MARKS, "linha atk-aaa\nlinha atk-bbb\nlinha atk-ccc")
    assert v.outcome is Outcome.FALSE_POSITIVE


def test_likely_when_partial() -> None:
    v = classify_logging(MARKS, "só atk-aaa apareceu")
    assert v.outcome is Outcome.LIKELY


def test_unconfirmed_when_no_markers() -> None:
    assert classify_logging([], "qualquer coisa").outcome is Outcome.UNCONFIRMED
