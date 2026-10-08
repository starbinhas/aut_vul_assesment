"""Memória de rastreio por alvo: acumula URLs e as devolve para semear o próximo scan."""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from scanner.common.db import (
    Base,
    CrawlMemory,
    get_known_routes,
    remember_routes,
)


@pytest.fixture
def sessions():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    return sessionmaker(engine, expire_on_commit=False)


def test_first_target_has_no_memory(sessions) -> None:
    assert get_known_routes(sessions, "target-x") == []


def test_remember_then_read_back(sessions) -> None:
    remember_routes(sessions, "t1", "scan-1", ["http://a/2", "http://a/1"])
    # Devolve ordenado e sem duplicatas.
    assert get_known_routes(sessions, "t1") == ["http://a/1", "http://a/2"]


def test_memory_is_monotonic_union(sessions) -> None:
    remember_routes(sessions, "t1", "scan-1", ["http://a/1", "http://a/2"])
    # Scan seguinte acha menos páginas: a memória NÃO encolhe, só acrescenta.
    remember_routes(sessions, "t1", "scan-2", ["http://a/2", "http://a/3"])
    assert get_known_routes(sessions, "t1") == ["http://a/1", "http://a/2", "http://a/3"]
    with sessions() as s:
        assert s.get(CrawlMemory, "t1").scan_id == "scan-2"  # registra o último que atualizou


def test_reprocessing_same_scan_is_idempotent(sessions) -> None:
    remember_routes(sessions, "t1", "scan-1", ["http://a/1", "http://a/2"])
    before = get_known_routes(sessions, "t1")
    remember_routes(sessions, "t1", "scan-1", ["http://a/1", "http://a/2"])
    assert get_known_routes(sessions, "t1") == before


def test_cap_limits_stored_routes(sessions) -> None:
    routes = [f"http://a/{i:04d}" for i in range(50)]
    remember_routes(sessions, "t1", "scan-1", routes, max_routes=10)
    stored = get_known_routes(sessions, "t1")
    assert len(stored) == 10
    assert stored == sorted(routes)[:10]


def test_memory_is_per_target(sessions) -> None:
    remember_routes(sessions, "t1", "scan-1", ["http://a/1"])
    remember_routes(sessions, "t2", "scan-2", ["http://b/1"])
    assert get_known_routes(sessions, "t1") == ["http://a/1"]
    assert get_known_routes(sessions, "t2") == ["http://b/1"]
