"""Detecção de arquivos sensíveis expostos (A04)."""

from __future__ import annotations

from scanner.common.models import Outcome
from scanner.validation.exposed_files import classify_exposure
from tests.conftest import resp

URL = "http://juice-shop:3000/ftp/acquisitions.md"
PATH = "/ftp/acquisitions.md"


def test_confirmed_when_file_is_readable() -> None:
    v = classify_exposure(PATH, URL, resp("conteúdo confidencial de verdade aqui", status=200))
    assert v.outcome is Outcome.CONFIRMED and v.proof is not None


def test_false_positive_when_denied() -> None:
    for status in (401, 403, 404):
        v = classify_exposure(PATH, URL, resp("", status=status))
        assert v.outcome is Outcome.FALSE_POSITIVE


def test_unconfirmed_when_200_but_empty() -> None:
    v = classify_exposure(PATH, URL, resp("  ", status=200))
    assert v.outcome is Outcome.UNCONFIRMED
