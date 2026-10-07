"""Núcleo puro do naabu: montagem do comando e parsing da saída JSONL."""

from __future__ import annotations

import json
from dataclasses import dataclass


@dataclass(frozen=True)
class DiscoveredPort:
    """Uma porta aberta encontrada pelo naabu em um host do escopo."""

    host: str
    ip: str
    port: int


def build_naabu_command(host: str, top_ports: str = "100") -> list[str]:
    """argv para rodar o naabu headless, em JSON e silencioso, para um único host.

    Pura: só monta a lista de argumentos; não executa nada.
    """
    return ["naabu", "-host", host, "-json", "-silent", "-top-ports", top_ports]


def parse_naabu_jsonl(text: str) -> list[DiscoveredPort]:
    """Converte a saída `-json` do naabu (um objeto JSON por linha) em portas descobertas.

    O naabu emite linhas como `{"ip":"1.2.3.4","port":80,"host":"example.com"}`; o `host` pode
    faltar (cai no `ip`). Pura: ignora linhas em branco, que não dão parse ou sem `port`.
    """
    ports: list[DiscoveredPort] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except (ValueError, TypeError):
            continue
        if not isinstance(obj, dict):
            continue
        port = obj.get("port")
        ip = obj.get("ip")
        if not isinstance(port, int) or not isinstance(ip, str):
            continue
        host = obj.get("host")
        host = host if isinstance(host, str) and host else ip
        ports.append(DiscoveredPort(host=host, ip=ip, port=port))
    return ports
