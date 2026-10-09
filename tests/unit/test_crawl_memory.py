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


# --- priorização da memória: guarda o que vale (parâmetro/API) ao estourar o teto ---------

from scanner.common.db import route_priority  # noqa: E402


def test_route_priority_order() -> None:
    assert route_priority("http://a/busca?q=1") == 3  # parâmetro
    assert route_priority("http://a/rest/users") == 2  # API
    assert route_priority("http://a/sobre") == 1  # página
    assert route_priority("http://a/app.js") == 0  # estático
    assert route_priority("http://a/logo.png") == 0


def test_static_assets_are_dropped_not_stored(sessions) -> None:
    static = [f"http://a/img{i:03d}.png" for i in range(20)]
    valuable = ["http://a/rest/products/search?q=x", "http://a/rest/admin", "http://a/login"]
    remember_routes(sessions, "t1", "s1", static + valuable, max_routes=50)
    stored = get_known_routes(sessions, "t1")
    # Estáticos não entram na memória (sem superfície de ataque); só os valiosos ficam.
    assert sorted(stored) == sorted(valuable)


def test_cap_keeps_higher_value_routes(sessions) -> None:
    params = [f"http://a/busca?q={i}&p={i}" for i in range(8)]  # distintos por valor? não:
    # mesma rota -> colapsam em 1; use caminhos distintos com parâmetro para testar o teto
    params = [f"http://a/p{i}?x=1" for i in range(8)]  # prioridade 3 (parâmetro)
    pages = [f"http://a/pag{i}" for i in range(8)]  # prioridade 1 (página)
    remember_routes(sessions, "t1", "s1", params + pages, max_routes=8)
    stored = get_known_routes(sessions, "t1")
    assert len(stored) == 8
    # Ao estourar o teto, as rotas com parâmetro (mais atacáveis) sobrevivem às páginas comuns.
    assert all("?x=1" in u for u in stored)


# --- assinatura de rota e convergência da memória -------------------------------------------

from scanner.common.db import (  # noqa: E402
    canonical_routes,
    has_repeated_segment,
    route_signature,
)


def test_route_signature_ignores_param_values() -> None:
    a = route_signature("http://a/busca?q=maca")
    b = route_signature("http://a/busca?q=pera")
    assert a == b == "http://a/busca?q"


def test_route_signature_sorts_param_names_and_drops_fragment() -> None:
    a = route_signature("http://a/x?b=1&a=2#frag")
    b = route_signature("http://a/x?a=9&b=8")
    assert a == b == "http://a/x?a,b"


def test_route_signature_normalizes_trailing_slash_and_case() -> None:
    assert route_signature("http://A/foo/") == route_signature("http://a/foo") == "http://a/foo"
    assert route_signature("http://a/") == "http://a/"  # raiz preservada


def test_canonical_routes_collapses_permutations_deterministically() -> None:
    urls = ["http://a/s?q=z", "http://a/s?q=a", "http://a/s?q=m", "http://a/outra"]
    assert canonical_routes(urls) == ["http://a/outra", "http://a/s?q=a"]  # representante = menor


def test_memory_converges_and_stops_growing(sessions) -> None:
    # Primeiro scan: uma rota de busca com um valor.
    remember_routes(sessions, "t1", "scan-1", ["http://a/busca?q=maca"])
    # Scan seguinte: a MESMA rota com outros valores não deve inflar a memória.
    remember_routes(sessions, "t1", "scan-2", ["http://a/busca?q=pera", "http://a/busca?q=uva"])
    stored = get_known_routes(sessions, "t1")
    assert len(stored) == 1  # convergiu: uma rota só, não inflou
    assert route_signature(stored[0]) == "http://a/busca?q"
    # Determinístico: reprocessar não muda o conjunto.
    remember_routes(sessions, "t1", "scan-3", ["http://a/busca?q=xyz"])
    assert get_known_routes(sessions, "t1") == stored


def test_has_repeated_segment_detects_spider_trap() -> None:
    assert has_repeated_segment("http://a/assets/assets")  # consecutivo
    assert has_repeated_segment("http://a/assets/i18n/assets/public")  # não consecutivo
    assert has_repeated_segment("http://a/x/x/x")
    assert not has_repeated_segment("http://a/rest/products/search?q=")
    assert not has_repeated_segment("http://a/assets/public/images/products")
    assert not has_repeated_segment("http://a/")


def test_canonical_routes_drops_spider_trap() -> None:
    # Profundidades e combinações variadas da armadilha são TODAS descartadas (lixo), reste a rota
    # limpa. O descarte não depende de quão fundo o rastreio foi — por isso é estável entre scans.
    urls = [f"http://a/{'data/' * n}x" for n in range(2, 50)]  # todas têm 'data' repetido
    urls += ["http://a/assets/public/report.pdf", "http://a/rest/user/login"]
    assert canonical_routes(urls) == [
        "http://a/assets/public/report.pdf",
        "http://a/rest/user/login",
    ]


def test_canonical_routes_drops_static_assets() -> None:
    urls = [
        "http://a/main.js",
        "http://a/styles.css",
        "http://a/logo.png",
        "http://a/fonts/icons.woff2",
        "http://a/rest/products/search?q=",  # mantém: superfície de ataque
        "http://a/ftp/coupons.md.bak",  # mantém: arquivo exposto (não é estático)
    ]
    assert canonical_routes(urls) == [
        "http://a/ftp/coupons.md.bak",
        "http://a/rest/products/search?q=",
    ]
