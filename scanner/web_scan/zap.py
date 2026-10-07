"""Dirige o ZAP via API: sessão nova, contexto do escopo, spiders, scan passivo e ativo."""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from zapv2 import ZAPv2

from scanner.common.models import Scope
from scanner.common.scope import ScopeGuard
from scanner.web_scan import policy

log = logging.getLogger(__name__)

POLL_SECONDS = 5


class ScanTimeoutError(Exception):
    pass


class ZapError(Exception):
    """O ZAP recusou um comando. O cliente `zaproxy` devolve o erro como texto, sem exceção."""


def _ok(result: Any, what: str) -> None:
    if result != "OK":
        raise ZapError(f"ZAP recusou '{what}': {result}")


def _scan_id(result: Any, what: str) -> str:
    if not str(result).isdigit():
        raise ZapError(f"ZAP não iniciou '{what}': {result}")
    return str(result)


@dataclass
class ScanLimits:
    max_duration_minutes: int
    threads_per_host: int
    max_requests_per_second: int


@dataclass
class HeaderCredential:
    """Credencial de teste injetada como cabeçalho (ex.: Authorization, Cookie)."""

    name: str
    value: str = field(repr=False)


class ZapScanner:
    """Um objeto por scan. Nunca compartilhar a instância do ZAP entre clientes ao mesmo tempo."""

    def __init__(
        self,
        api_url: str,
        api_key: str,
        limits: ScanLimits,
        on_progress: Callable[[str, int | None, str | None], None] | None = None,
    ) -> None:
        self.zap = ZAPv2(apikey=api_key, proxies={"http": api_url, "https": api_url})
        self.limits = limits
        self.on_progress = on_progress
        self._deadline = 0.0

    # --- preparação -----------------------------------------------------------------------

    def start_session(self, scan_id: str) -> None:
        _ok(self.zap.core.new_session(name=f"scan-{scan_id}", overwrite=True), "new_session")
        # Modo protegido: o ZAP só ataca URLs que estão no escopo do contexto.
        _ok(self.zap.core.set_mode("protect"), "set_mode protect")
        self._deadline = time.monotonic() + self.limits.max_duration_minutes * 60

    def create_context(self, scan_id: str, scope: Scope) -> tuple[str, str]:
        guard = ScopeGuard(scope)
        name = f"ctx-{scan_id}"
        context_id = _scan_id(self.zap.context.new_context(name), "new_context")
        for regex in guard.zap_include_regexes():
            _ok(self.zap.context.include_in_context(name, regex), "include_in_context")
        for regex in guard.zap_exclude_regexes():
            _ok(self.zap.context.exclude_from_context(name, regex), "exclude_from_context")
        _ok(self.zap.context.set_context_in_scope(name, True), "set_context_in_scope")
        return name, context_id

    def configure_limits(self) -> None:
        threads = self.limits.threads_per_host
        delay_ms = max(0, int(1000 * threads / self.limits.max_requests_per_second))
        minutes = self.limits.max_duration_minutes
        settings = [
            ("spider threads", self.zap.spider.set_option_thread_count(threads)),
            ("spider duração", self.zap.spider.set_option_max_duration(max(1, minutes // 4))),
            ("ajax duração", self.zap.ajaxSpider.set_option_max_duration(max(1, minutes // 4))),
            ("ajax browsers", self.zap.ajaxSpider.set_option_number_of_browsers(1)),
            ("ascan threads", self.zap.ascan.set_option_thread_per_host(threads)),
            ("ascan delay", self.zap.ascan.set_option_delay_in_ms(delay_ms)),
            ("ascan duração", self.zap.ascan.set_option_max_scan_duration_in_mins(minutes)),
            (
                "regra duração",
                self.zap.ascan.set_option_max_rule_duration_in_mins(max(1, minutes // 6)),
            ),
        ]
        for what, result in settings:
            _ok(result, what)

    def configure_policy(self, profile: policy.ScanProfile) -> None:
        names = self.zap.ascan.scan_policy_names
        if policy.POLICY_NAME in names:
            self.zap.ascan.remove_scan_policy(policy.POLICY_NAME)
        _ok(
            self.zap.ascan.add_scan_policy(
                policy.POLICY_NAME,
                alertthreshold=profile.alert_threshold,
                attackstrength=profile.attack_strength,
            ),
            "add_scan_policy",
        )

        if profile.rules is None:
            # Perfil agressivo (só laboratório): todas as regras instaladas.
            _ok(self.zap.ascan.enable_all_scanners(scanpolicyname=policy.POLICY_NAME), "enable_all")
        else:
            _ok(
                self.zap.ascan.disable_all_scanners(scanpolicyname=policy.POLICY_NAME),
                "disable_all",
            )
            # Uma regra inexistente faz o ZAP recusar a lista inteira: ligamos só as que existem.
            available = {s["id"] for s in self.zap.ascan.scanners(policy.POLICY_NAME)}
            wanted = {str(i) for i in profile.rules}
            if missing := sorted(wanted - available, key=int):
                log.warning("regras ausentes nesta versão do ZAP", extra={"rules": missing})
            ids = ",".join(sorted(wanted & available, key=int))
            _ok(
                self.zap.ascan.enable_scanners(ids, scanpolicyname=policy.POLICY_NAME),
                "enable_scanners",
            )
            enabled = {
                s["id"]
                for s in self.zap.ascan.scanners(policy.POLICY_NAME)
                if s["enabled"] == "true"
            }
            if not enabled or not enabled <= wanted:
                raise ZapError(f"política com regras inesperadas: {sorted(enabled, key=int)}")

        strength = profile.attack_strength
        if strength != "MEDIUM":
            for s in self.zap.ascan.scanners(policy.POLICY_NAME):
                if s["enabled"] == "true":
                    self.zap.ascan.set_scanner_attack_strength(
                        s["id"], strength, scanpolicyname=policy.POLICY_NAME
                    )
        log.info("política configurada", extra={"profile": profile.name})

    def set_credential(self, cred: HeaderCredential) -> None:
        """Injeta a credencial em toda requisição do ZAP (regra do add-on Replacer)."""
        result = self.zap.replacer.add_rule(
            description="scanner-credential",
            enabled=True,
            matchtype="REQ_HEADER",
            matchregex=False,
            matchstring=cred.name,
            replacement=cred.value,
        )
        _ok(result, "replacer.add_rule")

    # --- execução -------------------------------------------------------------------------

    def _wait(self, label: str, poll: Callable[[], tuple[bool, int | None, str | None]]) -> None:
        """Espera a fase terminar, reportando progresso a cada verificação.

        `poll()` devolve (terminou, pct 0-100 ou None, info curta ou None).
        """
        while True:
            done, pct, info = poll()
            if self.on_progress:
                self.on_progress(label, pct, info)
            if done:
                break
            if time.monotonic() > self._deadline:
                raise ScanTimeoutError(f"tempo máximo do scan estourado em: {label}")
            time.sleep(POLL_SECONDS)
        log.info("fase concluída", extra={"phase": label})

    def spider(self, url: str, context_name: str) -> None:
        scan = _scan_id(
            self.zap.spider.scan(url, contextname=context_name, subtreeonly=True), "spider"
        )

        def poll() -> tuple[bool, int | None, str | None]:
            pct = int(self.zap.spider.status(scan))
            found = len(self.zap.spider.results(scan))
            return pct >= 100, pct, f"{found} páginas encontradas"

        self._wait("spider", poll)

    def ajax_spider(self, url: str, context_name: str) -> None:
        _ok(
            self.zap.ajaxSpider.scan(url, inscope=True, contextname=context_name, subtreeonly=True),
            "ajax_spider",
        )

        def poll() -> tuple[bool, int | None, str | None]:
            # O AJAX spider não dá percentual; mostramos quantas URLs já achou.
            found = int(self.zap.ajaxSpider.number_of_results)
            return self.zap.ajaxSpider.status == "stopped", None, f"{found} páginas encontradas"

        self._wait("ajax_spider", poll)

    def seed_routes(self, routes: list[str], guard: ScopeGuard) -> None:
        """Rotas vindas das etapas 2/3 entram na árvore do ZAP (só se estiverem no escopo)."""
        for route in routes:
            if guard.allows(route):
                self.zap.core.access_url(route, followredirects=False)

    def passive_scan(self) -> None:
        def poll() -> tuple[bool, int | None, str | None]:
            remaining = int(self.zap.pscan.records_to_scan)
            return remaining == 0, None, f"{remaining} respostas na fila"

        self._wait("passive", poll)

    def active_scan(self, url: str, context_id: str) -> None:
        result = self.zap.ascan.scan(
            url,
            recurse=True,
            inscopeonly=True,
            scanpolicyname=policy.POLICY_NAME,
            contextid=context_id,
        )
        scan = _scan_id(result, "active_scan")

        def poll() -> tuple[bool, int | None, str | None]:
            pct = int(self.zap.ascan.status(scan))
            run: dict[str, Any] = next((s for s in self.zap.ascan.scans if s["id"] == scan), {})
            reqs = run.get("reqCount", 0)
            return pct >= 100, pct, f"{reqs} requisições enviadas"

        try:
            self._wait("active", poll)
        except ScanTimeoutError:
            self.zap.ascan.stop(scan)
            raise

    def alerts(self, base_url: str) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        start, page = 0, 500
        while True:
            batch = self.zap.core.alerts(baseurl=base_url, start=start, count=page)
            out.extend(batch)
            if len(batch) < page:
                return out
            start += page

    def message(self, message_id: str) -> dict[str, Any] | None:
        try:
            msg: dict[str, Any] = self.zap.core.message(message_id)
            return msg
        except Exception:
            log.warning("mensagem do ZAP indisponível", extra={"zap_message_id": message_id})
            return None
