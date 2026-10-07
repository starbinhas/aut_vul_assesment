"""Um validador por família de falha. Registro por regra do ZAP, template do nuclei ou CWE."""

from __future__ import annotations

from scanner.validation.validators import (
    cookies,
    headers,
    open_redirect,
    sqli_error,
    xss_reflected,
)
from scanner.validation.validators.base import Validator, registry, select

__all__ = ["Validator", "registry", "select"]

# Importar os módulos registra os validadores.
_ = (cookies, headers, open_redirect, sqli_error, xss_reflected)
