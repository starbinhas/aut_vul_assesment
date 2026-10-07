"""Orquestra o teste de controle de acesso entre dois usuários (etapa 5).

Junta as duas observações que `access_control.classify_access` compara: o dono acessando o próprio
recurso e um segundo usuário acessando o MESMO recurso. Só requisições de leitura (GET), pelo
`ProbeClient` (que recusa métodos que alteram dados). O worker de validação tem saída para o alvo.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from scanner.common.models import Validation
from scanner.validation.access_control import classify_access
from scanner.validation.http import ProbeClient


@dataclass
class Identity:
    """Uma sessão autenticada: o cabeçalho a injetar (ex.: Authorization: Bearer ...)."""

    header_name: str
    header_value: str = field(repr=False)  # token é sensível: fora do repr

    def as_header(self) -> dict[str, str]:
        return {self.header_name: self.header_value}


@dataclass
class AccessProbe:
    """Um recurso privado do dono e o marcador que prova que o dado é dele."""

    resource_url: str
    owner_marker: str


def run_access_probe(
    probe: AccessProbe, owner: Identity, other: Identity, client: ProbeClient
) -> Validation:
    """Lê o recurso como dono e como o outro usuário e devolve o veredito determinístico."""
    owner_resp = client.request("GET", probe.resource_url, headers=owner.as_header())
    other_resp = client.request("GET", probe.resource_url, headers=other.as_header())
    return classify_access(probe.resource_url, owner_resp, other_resp, probe.owner_marker)
