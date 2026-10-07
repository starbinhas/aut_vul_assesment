"""O núcleo puro da etapa 2: parsing da saída do naabu e montagem do comando."""

from __future__ import annotations

from scanner.recon.naabu import DiscoveredPort, build_naabu_command, parse_naabu_jsonl

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
