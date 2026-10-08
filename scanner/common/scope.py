"""Checagem de escopo: nenhuma requisição sai dos hosts/caminhos autorizados."""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from scanner.common.models import Scope


class OutOfScopeError(Exception):
    pass


class ScopeGuard:
    def __init__(self, scope: Scope) -> None:
        self.scope = scope
        self._hosts = {h.lower() for h in scope.allowed_hosts}
        self._include = [re.compile(p) for p in scope.include_paths]
        self._exclude = [re.compile(p) for p in scope.exclude_paths]

    def allows(self, url: str) -> bool:
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https"):
            return False
        host = (parts.hostname or "").lower()
        if host not in self._hosts:
            return False
        path = parts.path or "/"
        if any(p.search(path) for p in self._exclude):
            return False
        return not self._include or any(p.search(path) for p in self._include)

    def require(self, url: str) -> None:
        if not self.allows(url):
            raise OutOfScopeError(f"fora do escopo {self.scope.scope_id}: {url}")

    def zap_include_regexes(self) -> list[str]:
        """Regex de include para o contexto do ZAP (um por host)."""
        regexes = []
        for host in sorted(self._hosts):
            prefix = rf"https?://{re.escape(host)}(:\d+)?"
            if self._include:
                regexes += [prefix + p.pattern.removeprefix("^") for p in self._include]
            else:
                regexes.append(prefix + "(/.*)?")
        return regexes

    def zap_exclude_regexes(self) -> list[str]:
        out = []
        for host in sorted(self._hosts):
            prefix = rf"https?://{re.escape(host)}(:\d+)?"
            out += [prefix + ".*" + p.pattern.removeprefix("^") + ".*" for p in self._exclude]
        return out


def scope_for(target: object) -> Scope:
    """Escopo travado de um alvo verificado (etapa 1). `target` é um db.Target."""
    host = urlsplit(target.base_url).hostname or target.domain  # type: ignore[attr-defined]
    return Scope(
        scope_id=f"site-{target.target_id}",  # type: ignore[attr-defined]
        verified=True,
        locked=True,
        base_urls=[target.base_url],  # type: ignore[attr-defined]
        allowed_hosts=[host],
    )
