"""Arquivos/dados sensíveis expostos (A04) — detecção não destrutiva.

Alguns arquivos privados ficam acessíveis sem autenticação por descuido (documentos confidenciais,
chaves, backups). A prova é só <b>ler</b>: se o arquivo responde com conteúdo a quem não deveria,
está exposto. Nada é alterado nem removido — provar que a porta está destrancada é só abri-la.
"""

from __future__ import annotations

from scanner.common.models import Outcome, Validation
from scanner.validation.http import ProbeResponse
from scanner.validation.validators.base import proof_from, result

NAME = "exposed_sensitive_file"

# Caminhos sensíveis conhecidos (laboratório). Em cliente, a lista viria do escopo/descoberta.
SENSITIVE_PATHS: tuple[str, ...] = (
    "/ftp/acquisitions.md",  # documento confidencial
    "/encryptionkeys/premium.key",  # chave de criptografia
)

MIN_BODY = 16  # corpo mínimo para considerar que há conteúdo de verdade


def classify_exposure(path: str, url: str, resp: ProbeResponse, name: str = NAME) -> Validation:
    """Decide se um caminho sensível está exposto, a partir da resposta de um GET."""
    if resp.status == 200 and len(resp.text.strip()) >= MIN_BODY:
        proof = proof_from("GET", url, resp, None, f"arquivo sensível acessível: {path}")
        return result(
            name,
            Outcome.CONFIRMED,
            f"arquivo sensível acessível sem autenticação: {path}",
            proof,
        )
    if resp.status in (401, 403, 404):
        return result(
            name, Outcome.FALSE_POSITIVE, f"acesso negado a {path} (status {resp.status})"
        )
    return result(name, Outcome.UNCONFIRMED, f"resposta ambígua para {path} (status {resp.status})")
