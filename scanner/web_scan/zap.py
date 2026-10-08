"""Dirige o ZAP via API: sessão nova, contexto do escopo, spiders, scan passivo e ativo."""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

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


AJAX_MIN_EXPECTED = 20  # abaixo disso, o mapeamento do SPA provavelmente falhou


@dataclass
class ScanLimits:
    max_duration_minutes: int
    threads_per_host: int
    max_requests_per_second: int
    ajax_browsers: int = 1  # navegadores paralelos do AJAX spider (mais mapeia, mais RAM)


@dataclass
class HeaderCredential:
    """Credencial de teste injetada como cabeçalho (ex.: Authorization, Cookie)."""

    name: str
    value: str = field(repr=False)


@dataclass
class LoginCredential:
    """Faz login no alvo (pelo ZAP) e injeta o token obtido como cabeçalho.

    Para alvos que autenticam por token em JSON (ex.: Juice Shop:
    POST /rest/user/login -> {"authentication": {"token": "..."}}). O login é feito pelo ZAP,
    não pelo worker: só o ZAP tem saída para o alvo. A senha nunca aparece em log nem em repr.
    """

    login_url: str
    email: str
    password: str = field(repr=False)
    token_path: tuple[str, ...] = ("authentication", "token")
    header_name: str = "Authorization"
    header_template: str = "Bearer {token}"  # {token} é substituído pelo valor extraído


def extract_token(body: dict[str, Any], path: tuple[str, ...]) -> str:
    """Segue um caminho de chaves no JSON de resposta e devolve o token (texto não vazio)."""
    cur: Any = body
    for key in path:
        if not isinstance(cur, dict) or key not in cur:
            raise ZapError(
                f"token não encontrado no caminho '{'.'.join(path)}' da resposta de login"
            )
        cur = cur[key]
    if not isinstance(cur, str) or not cur:
        raise ZapError("token de login vazio ou não é texto")
    return cur


def build_login_request(spec: LoginCredential) -> str:
    """Requisição HTTP crua de login para o ZAP enviar (POST JSON com e-mail e senha)."""
    payload = json.dumps({"email": spec.email, "password": spec.password})
    host = urlsplit(spec.login_url).netloc
    return (
        f"POST {spec.login_url} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: {len(payload.encode())}\r\n\r\n"
        f"{payload}"
    )


def login_response_body(sent: Any) -> str:
    """Corpo da resposta devolvida por core.send_request (lista de mensagens ou dict).

    Em erro, o ZAP devolve uma string (ex.: 'mode_violation' quando a URL de login está fora do
    escopo do contexto): repassamos o motivo para o log, sem ficar com um erro genérico.
    """
    if isinstance(sent, str):
        raise ZapError(f"ZAP recusou o login: {sent}")
    msg = sent[-1] if isinstance(sent, list) and sent else sent
    if not isinstance(msg, dict):
        raise ZapError("resposta de login inesperada do ZAP")
    return msg.get("responseBody", "") or ""


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
            # AJAX spider endurecido: mais tempo, mais navegadores e ESPERA para o site em
            # JavaScript (SPA) terminar de renderizar antes de coletar os links — sem isso o
            # mapeamento de sites como o Juice Shop sai curto e varia de uma execução para outra.
            ("ajax duração", self.zap.ajaxSpider.set_option_max_duration(max(2, minutes // 2))),
            (
                "ajax browsers",
                self.zap.ajaxSpider.set_option_number_of_browsers(self.limits.ajax_browsers),
            ),
            ("ajax profundidade", self.zap.ajaxSpider.set_option_max_crawl_depth(10)),
            ("ajax espera recarga", self.zap.ajaxSpider.set_option_reload_wait(3000)),
            ("ajax espera evento", self.zap.ajaxSpider.set_option_event_wait(1500)),
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

    def login(self, spec: LoginCredential) -> HeaderCredential:
        """Autentica no alvo pelo ZAP e devolve o cabeçalho com o token, para injetar no scan.

        O ZAP faz o POST de login (só ele tem saída para o alvo); extraímos o token do JSON e
        montamos o cabeçalho. Limitação: se o token expirar no meio do scan, não há reautenticação
        automática (área logada exige scan dentro do tempo de validade do token).
        """
        sent = self.zap.core.send_request(build_login_request(spec), followredirects=True)
        try:
            body = json.loads(login_response_body(sent))
        except (json.JSONDecodeError, TypeError) as exc:
            raise ZapError("resposta de login não é JSON válido") from exc
        token = extract_token(body, spec.token_path)
        log.info("login efetuado", extra={"header": spec.header_name})
        return HeaderCredential(
            name=spec.header_name, value=spec.header_template.format(token=token)
        )

    CREDENTIAL_RULE = "scanner-credential"

    def set_credential(self, cred: HeaderCredential) -> None:
        """Injeta a credencial em toda requisição do ZAP (regra do add-on Replacer).

        O Replacer é global, não faz parte da sessão: uma regra de um scan anterior na mesma
        instância do ZAP sobra e causaria 'already_exists'. Removemos antes de criar (idempotente).
        """
        self.zap.replacer.remove_rule(description=self.CREDENTIAL_RULE)  # ignora se não existir
        result = self.zap.replacer.add_rule(
            description=self.CREDENTIAL_RULE,
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

    def crawled_urls(self, base_url: str) -> list[str]:
        """URLs que o rastreio alcançou dentro do alvo (fonte da cobertura e da memória)."""
        urls = self.zap.core.urls(base_url)
        return [u for u in urls if isinstance(u, str)] if isinstance(urls, list) else []

    def crawled_count(self, base_url: str) -> int:
        """Quantas páginas (URLs) o rastreio alcançou dentro do alvo — mede a cobertura."""
        return len(self.crawled_urls(base_url))

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
