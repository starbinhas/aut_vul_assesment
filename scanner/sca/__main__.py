"""CLI do scan de componentes: recebe o manifesto do cliente e aponta as dependências vulneráveis.

python -m scanner.sca <caminho-do-manifesto>   # package-lock.json, package.json, requirements.txt
"""

from __future__ import annotations

import sys

from scanner.sca.manifest import load_manifest
from scanner.sca.service import scan_manifest


def main() -> None:
    if len(sys.argv) != 2:
        sys.exit("uso: python -m scanner.sca <caminho-do-manifesto>")
    path = sys.argv[1]
    total = len(load_manifest(path))
    results = scan_manifest(path)
    print(f"\nScan de componentes — {path}")
    print(f"dependências lidas: {total} | com falha conhecida: {len(results)}\n")
    if not results:
        print("Nenhuma dependência com falha conhecida. ")
        return
    for r in results:
        c = r.component
        print(f"• {c.name} {c.version} ({c.ecosystem}) — {len(r.vulns)} falha(s):")
        for v in r.vulns[:5]:
            print(f"    [{v.severity}] {v.id} {('- ' + v.summary) if v.summary else ''}")
        if len(r.vulns) > 5:
            print(f"    … e mais {len(r.vulns) - 5}")


if __name__ == "__main__":
    main()
