"""SQL injection baseada em erro: aspa simples gera erro de banco, aspa dobrada não."""

from __future__ import annotations

import re

from scanner.common.models import Finding, Outcome, Validation
from scanner.validation.http import ProbeClient
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
        return result(NAME, Outcome.UNCONFIRMED, "aspa simples não gerou erro de banco visível")

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
