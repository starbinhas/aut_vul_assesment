"""O núcleo puro da etapa 2: parsing da saída do naabu e montagem do comando."""

from __future__ import annotations

from scanner.common.models import Scope
from scanner.recon.naabu import DiscoveredPort, build_naabu_command, parse_naabu_jsonl
from scanner.recon.openapi import parse_openapi
from scanner.recon.service import cve_targets

FIXTURE = """\
{"ip":"1.2.3.4","port":80,"host":"example.com"}

{"ip":"1.2.3.4","port":443,"host":"example.com"}
{"ip":"5.6.7.8","port":22}
isto nao e json
{"ip":"9.9.9.9"}
"""


def test_parse_extrai_portas_validas() -> None:
    ports = parse_naabu_jsonl(FIXTURE)
    assert ports == [
        DiscoveredPort(host="example.com", ip="1.2.3.4", port=80),
        DiscoveredPort(host="example.com", ip="1.2.3.4", port=443),
        DiscoveredPort(host="5.6.7.8", ip="5.6.7.8", port=22),
    ]


def test_parse_usa_ip_quando_host_ausente() -> None:
    (p,) = parse_naabu_jsonl('{"ip":"5.6.7.8","port":22}')
    assert p.host == "5.6.7.8" and p.ip == "5.6.7.8" and p.port == 22


def test_parse_ignora_vazio_malformado_e_sem_porta() -> None:
    assert parse_naabu_jsonl("") == []
    assert parse_naabu_jsonl("\n   \n") == []
    assert parse_naabu_jsonl("{bagunça}") == []
    assert parse_naabu_jsonl('{"ip":"9.9.9.9"}') == []


def test_build_command_padrao() -> None:
    assert build_naabu_command("example.com") == [
        "naabu",
        "-host",
        "example.com",
        "-json",
        "-silent",
        "-top-ports",
        "100",
    ]


def test_build_command_top_ports_customizado() -> None:
    cmd = build_naabu_command("juice-shop", top_ports="1000")
    assert cmd[-2:] == ["-top-ports", "1000"]
    assert "-host" in cmd and "juice-shop" in cmd


def _scope() -> Scope:
    return Scope(
        scope_id="s",
        verified=True,
        locked=True,
        base_urls=["http://juice-shop:3000/"],
        allowed_hosts=["juice-shop"],
    )


def test_cve_targets_inclui_base_e_portas_web_em_escopo() -> None:
    ports = [
        DiscoveredPort(host="juice-shop", ip="1.2.3.4", port=8080),  # web -> inclui
        DiscoveredPort(host="juice-shop", ip="1.2.3.4", port=22),  # SSH -> ignora
        DiscoveredPort(host="evil.com", ip="9.9.9.9", port=80),  # fora do escopo -> ignora
    ]
    targets = cve_targets(_scope(), ports)
    assert "http://juice-shop:3000/" in targets  # base_url sempre
    assert "http://juice-shop:8080/" in targets  # porta web descoberta
    assert all("evil.com" not in t for t in targets)
    assert all(":22" not in t for t in targets)


def test_cve_targets_sem_portas_usa_so_base() -> None:
    assert cve_targets(_scope(), []) == ["http://juice-shop:3000/"]


def test_parse_openapi_v3_fills_path_and_query_params() -> None:
    spec = {
        "openapi": "3.0.0",
        "servers": [{"url": "/api"}],
        "paths": {
            "/users/{id}": {"get": {"parameters": [{"name": "fields", "in": "query"}]}},
            "/health": {"get": {}},
        },
    }
    routes = parse_openapi(spec, "http://juice-shop:3000/")
    assert "http://juice-shop:3000/api/users/1?fields=1" in routes
    assert "http://juice-shop:3000/api/health" in routes


def test_parse_openapi_v2_uses_basepath() -> None:
    spec = {"swagger": "2.0", "basePath": "/v1", "paths": {"/orders": {"get": {}}}}
    assert parse_openapi(spec, "http://juice-shop:3000/") == ["http://juice-shop:3000/v1/orders"]


def test_parse_openapi_ignores_malformed() -> None:
    assert parse_openapi({"openapi": "3.0.0"}, "http://x/") == []  # sem paths
    assert parse_openapi({"paths": "nope"}, "http://x/") == []
