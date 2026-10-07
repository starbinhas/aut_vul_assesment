"""Lê a 'lista de ingredientes' (manifesto de dependências) que o cliente fornece.

Suporta o lockfile do npm (package-lock.json, mais preciso: traz a versão exata) e, como apoio,
package.json e requirements.txt. O cliente não precisa entregar o código todo — só este arquivo.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from scanner.sca.models import Component

_RANGE = re.compile(r"^[\^~>=<\s]+")


def _clean_version(v: str) -> str:
    return _RANGE.sub("", v.strip()).split(" ")[0]


def parse_package_lock(data: dict[str, Any]) -> list[Component]:
    """npm package-lock.json (lockfileVersion 2/3: chave 'packages'; v1: 'dependencies')."""
    out: list[Component] = []
    packages = data.get("packages")
    if isinstance(packages, dict):
        for path, info in packages.items():
            if not path or not isinstance(info, dict) or "version" not in info:
                continue  # "" é o próprio projeto
            name = path.split("node_modules/")[-1]
            out.append(Component("npm", name, str(info["version"])))
        return out

    def walk(deps: dict[str, Any]) -> None:
        for name, info in deps.items():
            if isinstance(info, dict) and "version" in info:
                out.append(Component("npm", name, str(info["version"])))
                if isinstance(info.get("dependencies"), dict):
                    walk(info["dependencies"])

    if isinstance(data.get("dependencies"), dict):
        walk(data["dependencies"])
    return out


def parse_package_json(data: dict[str, Any]) -> list[Component]:
    """package.json: versões podem ser faixas (^4.17.4); melhor esforço."""
    out: list[Component] = []
    for key in ("dependencies", "devDependencies"):
        for name, spec in (data.get(key) or {}).items():
            version = _clean_version(str(spec))
            if version:
                out.append(Component("npm", name, version))
    return out


def parse_requirements(text: str) -> list[Component]:
    """requirements.txt do Python: linhas 'nome==versão'."""
    out: list[Component] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "==" not in line:
            continue
        name, _, version = line.partition("==")
        out.append(Component("PyPI", name.strip(), _clean_version(version)))
    return out


def load_manifest(path: str | Path) -> list[Component]:
    p = Path(path)
    name = p.name.lower()
    if name == "package-lock.json":
        return parse_package_lock(json.loads(p.read_text()))
    if name == "package.json":
        return parse_package_json(json.loads(p.read_text()))
    if name.startswith("requirements") and name.endswith(".txt"):
        return parse_requirements(p.read_text())
    raise ValueError(
        f"manifesto não suportado: {p.name} (use package-lock.json/package.json/requirements.txt)"
    )
