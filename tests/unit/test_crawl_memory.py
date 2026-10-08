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


# --- regressão de cobertura: baseline do scan anterior -----------------------------------

from datetime import datetime  # noqa: E402

from scanner.common.db import Scan, last_pages_crawled  # noqa: E402


def _add_scan(sessions, scan_id, target_id, pages, created):
    with sessions.begin() as s:
        s.add(
            Scan(
                scan_id=scan_id,
                target_id=target_id,
                scope={},
                pages_crawled=pages,
                created_at=created,
            )
        )


def test_last_pages_crawled_none_when_no_history(sessions) -> None:
    assert last_pages_crawled(sessions, "t1", "scan-now") is None


def test_last_pages_crawled_picks_most_recent_other_scan(sessions) -> None:
    _add_scan(sessions, "s1", "t1", 100, datetime(2026, 1, 1))
    _add_scan(sessions, "s2", "t1", 800, datetime(2026, 2, 1))
    _add_scan(sessions, "s3", "t2", 999, datetime(2026, 3, 1))  # outro alvo, ignorado
    assert last_pages_crawled(sessions, "t1", "scan-now") == 800


def test_last_pages_crawled_excludes_current_scan(sessions) -> None:
    _add_scan(sessions, "s1", "t1", 100, datetime(2026, 1, 1))
    _add_scan(sessions, "cur", "t1", 5, datetime(2026, 2, 1))  # o scan em curso não é baseline
    assert last_pages_crawled(sessions, "t1", "cur") == 100


def test_last_pages_crawled_ignores_unmeasured(sessions) -> None:
    _add_scan(sessions, "s1", "t1", None, datetime(2026, 2, 1))
    _add_scan(sessions, "s2", "t1", 100, datetime(2026, 1, 1))
    assert last_pages_crawled(sessions, "t1", "scan-now") == 100


# --- should_recrawl (função pura) --------------------------------------------------------

from scanner.web_scan.service import should_recrawl  # noqa: E402


def test_recrawl_when_below_minimum() -> None:
    assert should_recrawl(5, min_pages=15, previous=None, regression_ratio=0.7) is True


def test_no_recrawl_when_healthy_and_no_history() -> None:
    assert should_recrawl(100, min_pages=15, previous=None, regression_ratio=0.7) is False


def test_recrawl_on_regression_vs_previous() -> None:
    # Anterior cobriu 800; hoje 300 (<70%): regressão -> refaz.
    assert should_recrawl(300, min_pages=15, previous=800, regression_ratio=0.7) is True


def test_no_recrawl_when_near_previous() -> None:
    # 600 de 800 (75% >= 70%): aceitável, não refaz.
    assert should_recrawl(600, min_pages=15, previous=800, regression_ratio=0.7) is False


# --- entrega parcial / sinal de parada (alvo instável) -----------------------------------

from scanner.common.db import (  # noqa: E402
    is_stop_requested,
    mark_partial,
    request_stop,
)


def _add_bare_scan(sessions, scan_id="s1", target_id="t1"):
    with sessions.begin() as s:
        s.add(Scan(scan_id=scan_id, target_id=target_id, scope={}))


def test_stop_request_round_trips(sessions) -> None:
    _add_bare_scan(sessions)
    assert is_stop_requested(sessions, "s1") is False
    request_stop(sessions, "s1")
    assert is_stop_requested(sessions, "s1") is True


def test_request_stop_is_idempotent_keeps_first_time(sessions) -> None:
    _add_bare_scan(sessions)
    request_stop(sessions, "s1")
    with sessions() as s:
        first = s.get(Scan, "s1").stop_requested_at
    request_stop(sessions, "s1")  # segunda vez não sobrescreve
    with sessions() as s:
        assert s.get(Scan, "s1").stop_requested_at == first


def test_mark_partial_sets_flag_and_reason(sessions) -> None:
    _add_bare_scan(sessions)
    mark_partial(sessions, "s1", "target-unstable")
    with sessions() as s:
        scan = s.get(Scan, "s1")
        assert scan.partial is True
        assert scan.partial_reason == "target-unstable"
