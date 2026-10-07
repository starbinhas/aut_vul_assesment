"""Cliente HTTP das provas: só dentro do escopo, sem seguir redirect, só métodos seguros."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field

import httpx

from scanner.common.scope import ScopeGuard

SAFE_METHODS = frozenset({"GET", "HEAD"})
MAX_BODY_BYTES = 512 * 1024
USER_AGENT = "scanner-validation/0.1"


class UnsafeRequestError(Exception):
    pass


@dataclass
class ProbeResponse:
    status: int
    headers: httpx.Headers
    text: str
    url: str
    set_cookies: list[str] = field(default_factory=list)


class ProbeClient:
    """Interface que os validadores usam. Em testes, troque por um fake."""

    def __init__(self, guard: ScopeGuard, max_rps: int = 5, timeout: float = 15.0) -> None:
        self.guard = guard
        self._min_interval = 1.0 / max_rps
        self._last = 0.0
        self._lock = threading.Lock()
        self._http = httpx.Client(
            follow_redirects=False,  # redirect pode sair do escopo
            timeout=timeout,
            headers={"User-Agent": USER_AGENT},
            verify=True,
        )

    def _throttle(self) -> None:
        with self._lock:
            wait = self._last + self._min_interval - time.monotonic()
            if wait > 0:
                time.sleep(wait)
            self._last = time.monotonic()

    def request(
        self, method: str, url: str, headers: dict[str, str] | None = None
    ) -> ProbeResponse:
        method = method.upper()
        if method not in SAFE_METHODS:
            raise UnsafeRequestError(f"método {method} não é usado em provas (pode alterar dados)")
        self.guard.require(url)
        self._throttle()
        with self._http.stream(method, url, headers=headers) as resp:
            body = b""
            for chunk in resp.iter_bytes():
                body += chunk
                if len(body) >= MAX_BODY_BYTES:
                    break
            return ProbeResponse(
                status=resp.status_code,
                headers=resp.headers,
                text=body[:MAX_BODY_BYTES].decode(resp.encoding or "utf-8", errors="replace"),
                url=str(resp.url),
                set_cookies=resp.headers.get_list("set-cookie"),
            )

    def close(self) -> None:
        self._http.close()
