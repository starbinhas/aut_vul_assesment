"""Capturas de tela da interface, para revisar o visual antes de entregar (ver CLAUDE.md).

Entra com um usuário, percorre as telas do cliente (e do admin, se o usuário for admin) em desktop
e celular, e grava PNGs em página inteira. Junto, registra o que dá para conferir de forma
automática: erros de console (inclusive violação de CSP), requisições que falharam e rolagem
horizontal no celular.

Só roda contra a interface local: as telas mostram dados de cliente, e as capturas ficam em
`out/` (fora do git).

    uv run playwright install chromium        # uma vez
    UI_SHOTS_EMAIL=... UI_SHOTS_PASSWORD=... uv run python -m tests.ui_shots
    uv run python -m tests.ui_shots --only painel,scan --viewport mobile
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from playwright.sync_api import Browser, Page, sync_playwright

LOCAL_HOSTS = {"127.0.0.1", "localhost", "web"}
VIEWPORTS = {"desktop": (1440, 900), "mobile": (390, 844)}

# (nome, caminho). Caminhos com {…} são descobertos seguindo links de outra tela.
CLIENT_PAGES = [
    ("painel", "/painel"),
    ("sites", "/sites"),
    ("site-novo", "/sites/novo"),
    ("site", "{site}"),
    ("scan", "{scan}"),
    ("scan-item", "{scan}"),
    ("relatorio", "{scan}/relatorio.html"),
    ("copia-de-teste", "{copia}"),
    ("copia-resiliencia", "{copia}?nivel=stress"),
    ("conta", "/conta"),
]
# Capturas de um elemento aberto, não da página: o item de falha expandido (com o recibo da
# prova, se houver algum) é a tela que o cliente mais usa e fica fechado por padrão.
EXPAND = {"scan-item": ("details.issue:has(.proof)", "details.issue")}
ADMIN_PAGES = [
    ("admin-operacao", "/admin"),
    ("admin-clientes", "/admin/clientes"),
    ("admin-cliente", "{org}"),
    ("admin-scans", "/admin/scans"),
    ("admin-fila", "/admin/operacao"),
    ("admin-auditoria", "/admin/auditoria"),
    ("admin-equipe", "/admin/equipe"),
    ("admin-copias", "/admin/copias-de-teste"),
]
# Onde procurar o primeiro link de cada caminho dinâmico. A origem pode ser outra dinâmica
# (ex.: a cópia de teste só é linkada na página do site), resolvida por `found`.
DISCOVER = {
    "site": ("/sites", r"^/sites/(?!novo)[^/#?]+$"),
    "scan": ("/painel", r"^/scans/[^/#?]+$"),
    "org": ("/admin/clientes", r"^/admin/clientes/[^/#?]+$"),
    "copia": ("{site}", r"^/sites/[^/#?]+/copia-de-teste$"),
}


@dataclass
class Shot:
    name: str
    viewport: str
    path: str
    file: str = ""
    status: int | None = None
    console: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)
    overflow_px: int = 0


def _check_local(base: str) -> None:
    host = urlsplit(base).hostname or ""
    if host not in LOCAL_HOSTS:
        sys.exit(f"recusado: {host!r} não é a interface local ({', '.join(sorted(LOCAL_HOSTS))})")


def _login(page: Page, base: str, email: str, password: str) -> None:
    page.goto(f"{base}/entrar")
    page.fill("#email", email)
    page.fill("#password", password)
    page.click("button[type=submit]")
    page.wait_for_load_state("load")
    if urlsplit(page.url).path == "/entrar":
        # Para na primeira falha: a conta bloqueia após 5 tentativas.
        sys.exit("login falhou (confira UI_SHOTS_EMAIL / UI_SHOTS_PASSWORD)")


def _discover(page: Page, base: str, key: str, found: dict[str, str | None]) -> str | None:
    source, pattern = DISCOVER[key]
    if source.startswith("{"):  # origem dinâmica (ex.: a cópia só é linkada na página do site)
        dep, _, suffix = source[1:].partition("}")
        if found.get(dep) is None:
            return None
        source = found[dep] + suffix
    page.goto(f"{base}{source}")
    for href in page.eval_on_selector_all("a[href]", "els => els.map(e => e.getAttribute('href'))"):
        path = (href or "").split("#")[0]
        if re.match(pattern, path):
            return path
    return None


def _capture(page: Page, base: str, shot: Shot, out: Path) -> None:
    console: list[str] = []
    failed: list[str] = []
    page.on(
        "console",
        lambda m: console.append(f"{m.type}: {m.text}") if m.type in {"error", "warning"} else None,
    )
    page.on("pageerror", lambda e: console.append(f"pageerror: {e}"))
    page.on("requestfailed", lambda r: failed.append(f"{r.method} {r.url} ({r.failure})"))
    page.on("response", lambda r: failed.append(f"{r.status} {r.url}") if r.status >= 400 else None)

    response = page.goto(f"{base}{shot.path}", wait_until="load")
    # Telas com HTMX em polling (andamento do scan) nunca ficam ociosas: espera curta e fixa.
    page.wait_for_timeout(600)
    shot.status = response.status if response else None
    shot.overflow_px = int(
        page.evaluate("document.documentElement.scrollWidth - document.documentElement.clientWidth")
    )
    shot.file = f"{shot.name}.{shot.viewport}.png"
    for selector in EXPAND.get(shot.name, ()):
        element = page.locator(selector).first
        if element.count():
            element.evaluate("e => { e.open = true; }")
            element.screenshot(path=out / shot.file)
            break
    else:
        page.screenshot(path=out / shot.file, full_page=True)
    shot.console, shot.failed = console, failed


def run(
    base: str,
    email: str,
    password: str,
    only: set[str],
    viewports: list[str],
    out: Path,
    motion: bool = False,
) -> list[Shot]:
    out.mkdir(parents=True, exist_ok=True)
    shots: list[Shot] = []
    with sync_playwright() as p:
        # Sem isso, o Chromium headless no Linux arredonda a posição de cada letra e o texto
        # pequeno sai com espaçamento irregular que não existe nos navegadores dos clientes.
        browser: Browser = p.chromium.launch(args=["--font-render-hinting=none"])
        for vp in viewports:
            w, h = VIEWPORTS[vp]
            ctx = browser.new_context(
                viewport={"width": w, "height": h},
                locale="pt-BR",
                color_scheme="dark",
                device_scale_factor=1,
                # Estado final das telas, sem animação pela metade (e testa o modo reduzido).
                reduced_motion="no-preference" if motion else "reduce",
            )
            nav = ctx.new_page()  # login e descoberta de links; cada captura usa uma aba nova

            if not only or "entrar" in only:
                s = Shot("entrar", vp, "/entrar")
                _capture(nav, base, s, out)
                shots.append(s)

            _login(nav, base, email, password)
            pages = list(CLIENT_PAGES)
            if nav.locator(".admin-tag").count():
                pages += ADMIN_PAGES

            found: dict[str, str | None] = {}
            for name, path in pages:
                if only and name not in only:
                    continue
                if path.startswith("{"):
                    key, _, suffix = path[1:].partition("}")
                    if key not in found:
                        found[key] = _discover(nav, base, key, found)
                    if not found[key]:
                        print(f"pulada: {name} (nenhum link para {key})")
                        continue
                    path = found[key] + suffix
                s = Shot(name, vp, path)
                page = ctx.new_page()  # aba nova: ouvintes de console não se acumulam
                _capture(page, base, s, out)
                page.close()
                shots.append(s)
            ctx.close()
        browser.close()
    return shots


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--base", default=os.environ.get("UI_SHOTS_URL", "http://127.0.0.1:8000"))
    ap.add_argument("--only", default="", help="nomes separados por vírgula (ex.: painel,scan)")
    ap.add_argument("--viewport", choices=[*VIEWPORTS, "all"], default="all")
    ap.add_argument("--out", type=Path, default=Path("out/ui-shots"))
    ap.add_argument("--motion", action="store_true", help="capturar com animações ligadas")
    args = ap.parse_args()

    base = args.base.rstrip("/")
    _check_local(base)
    email, password = os.environ.get("UI_SHOTS_EMAIL"), os.environ.get("UI_SHOTS_PASSWORD")
    if not email or not password:
        sys.exit("defina UI_SHOTS_EMAIL e UI_SHOTS_PASSWORD (usuário da interface local)")

    only = {n for n in args.only.split(",") if n}
    viewports = list(VIEWPORTS) if args.viewport == "all" else [args.viewport]
    shots = run(base, email, password, only, viewports, args.out, args.motion)

    (args.out / "report.json").write_text(
        json.dumps([s.__dict__ for s in shots], ensure_ascii=False, indent=2)
    )
    problems = 0
    for s in shots:
        flags = []
        if s.status and s.status >= 400:
            flags.append(f"HTTP {s.status}")
        if s.overflow_px > 0:
            flags.append(f"rolagem horizontal {s.overflow_px}px")
        flags += s.console + s.failed
        problems += bool(flags)
        print(f"{s.file:34} {s.path:40} {'; '.join(flags) or 'ok'}")
    print(f"\n{len(shots)} capturas em {args.out}/, {problems} com alerta")


if __name__ == "__main__":
    main()
