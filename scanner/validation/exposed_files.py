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

# Caminhos sensíveis que ficam expostos por descuido em sites reais: controle de versão, segredos,
# backups, dumps e configuração. Cada um é um GET não destrutivo. A lista do laboratório (Juice
# Shop) fica no fim para os testes. `extra_paths` (de descoberta/escopo) é somado a esta base.
COMMON_SENSITIVE_PATHS: tuple[str, ...] = (
    # Controle de versão exposto (vaza todo o código e o histórico)
    "/.git/config",
    "/.git/HEAD",
    "/.svn/entries",
    "/.hg/hgrc",
    # Segredos e variáveis de ambiente
    "/.env",
    "/.env.local",
    "/.env.production",
    "/config/secrets.yml",
    "/credentials.json",
    "/.aws/credentials",
    "/.npmrc",
    # Backups e dumps (senhas, dados de clientes)
    "/backup.zip",
    "/backup.sql",
    "/database.sql",
    "/dump.sql",
    "/db.sqlite",
    "/.env.bak",
    "/wp-config.php.bak",
    "/web.config.bak",
    # Configuração e metadados de deploy
    "/docker-compose.yml",
    "/.dockercfg",
    "/.DS_Store",
    "/phpinfo.php",
    "/server-status",
    "/.htpasswd",
)

# Caminhos do laboratório (Juice Shop), mantidos para as provas de integração locais.
LAB_SENSITIVE_PATHS: tuple[str, ...] = (
    "/ftp/acquisitions.md",  # documento confidencial
    "/encryptionkeys/premium.key",  # chave de criptografia
)

SENSITIVE_PATHS: tuple[str, ...] = COMMON_SENSITIVE_PATHS + LAB_SENSITIVE_PATHS

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
