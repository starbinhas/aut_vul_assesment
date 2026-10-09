"""SQL injection: erro de banco (aspa simples) e, sem erro, inferência booleana (cega).

Duas provas, da mais forte para a mais fraca, ambas só de leitura (sem OR/UNION/stacked/time):
- baseada em erro: aspa simples gera erro de banco, aspa dobrada não;
- booleana (cega): uma condição VERDADEIRA preserva a resposta e uma FALSA a altera. Confirma só com
  sinal forte (verdadeira ~ original, falsa claramente diferente), para não gerar falso positivo em
  páginas dinâmicas.
"""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlsplit

from scanner.common.models import Finding, Outcome, Validation
from scanner.validation.http import ProbeClient, ProbeResponse
from scanner.validation.validators.base import (
    is_query_param,
    proof_from,
    register,
    result,
    with_param,
)

NAME = "sqli_error"

DB_ERRORS = re.compile(
    r"SQL syntax.*?MySQL|Warning.*?\bmysqli?_|MySqlException|valid MySQL result"
    r"|PostgreSQL.*?ERROR|pg_query\(\)|PSQLException|unterminated quoted string"
    r"|ORA-\d{5}|Oracle error|SQLServer JDBC Driver|Unclosed quotation mark"
    r"|Microsoft OLE DB Provider for SQL Server|SQLITE_ERROR|sqlite3\.OperationalError"
    r"|SQLiteException|near \".*?\": syntax error|SQLSTATE\[",
    re.IGNORECASE,
)


def _error(text: str) -> str | None:
    m = DB_ERRORS.search(text)
    return m.group(0) if m else None


def _param_value(url: str, param: str) -> str:
    for k, v in parse_qsl(urlsplit(url).query, keep_blank_values=True):
        if k == param:
            return v
    return ""


def _similar(a: ProbeResponse, base: ProbeResponse) -> bool:
    """Mesma resposta, na prática: mesmo status e tamanho de corpo dentro de 2% (ou 32 bytes)."""
    tol = max(32, len(base.text) // 50)
    return a.status == base.status and abs(len(a.text) - len(base.text)) <= tol


def _different(a: ProbeResponse, base: ProbeResponse) -> bool:
    """Resposta claramente diferente: outro status, ou tamanho divergindo >10% (ou 64 bytes)."""
    tol = max(64, len(base.text) // 10)
    return a.status != base.status or abs(len(a.text) - len(base.text)) > tol


def _boolean_check(
    f: Finding, client: ProbeClient, url: str, param: str, base: ProbeResponse
) -> Validation:
    """SQLi booleano cego: condição verdadeira preserva a resposta, falsa a altera. Só leitura."""
    orig = _param_value(url, param)
    true_url = with_param(url, param, f"{orig}' AND '1'='1")
    false_url = with_param(url, param, f"{orig}' AND '1'='2")
    true_resp = client.request("GET", true_url)
    false_resp = client.request("GET", false_url)
    if _similar(true_resp, base) and _different(false_resp, base):
        proof = proof_from(
            "GET",
            false_url,
            false_resp,
            None,
            "condição falsa muda a resposta; condição verdadeira a mantém (SQLi booleano)",
        )
        return result(
            NAME,
            Outcome.CONFIRMED,
            f"o parâmetro '{param}' altera a lógica da consulta SQL (inferência booleana)",
            proof,
        )
    return result(
        NAME, Outcome.UNCONFIRMED, "sem erro de banco e sem diferença booleana conclusiva"
    )


@register(NAME, zap_rules=("40018",), cwes=(89,))
def validate(f: Finding, client: ProbeClient) -> Validation:
    url, param = f.location.url, f.location.parameter
    if f.location.method != "GET" or not is_query_param(url, param):
        return result(
            NAME, Outcome.UNCONFIRMED, "prova automática só para parâmetros de query em GET"
        )
    assert param is not None

    # Só leitura: não usamos OR/UNION/stacked queries, apenas quebramos a sintaxe da string.
    base = client.request("GET", with_param(url, param, "1"))
    if _error(base.text):
        return result(NAME, Outcome.UNCONFIRMED, "a página já mostra erro de banco sem injeção")

    quote_url = with_param(url, param, "1'")
    quote = client.request("GET", quote_url)
    err = _error(quote.text)
    if not err:
        # Sem erro visível: tenta a inferência booleana (cega) a partir da resposta original.
        original = client.request("GET", url)
        return _boolean_check(f, client, url, param, original)

    doubled = client.request("GET", with_param(url, param, "1''"))
    proof = proof_from("GET", quote_url, quote, err, f"erro de banco com aspa simples: {err}")
    if _error(doubled.text):
        return result(
            NAME, Outcome.LIKELY, "erro de banco com aspa simples e também com aspa dobrada", proof
        )
    return result(
        NAME,
        Outcome.CONFIRMED,
        f"o parâmetro '{param}' quebra a consulta SQL (erro de banco)",
        proof,
    )
