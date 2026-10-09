"""Scan de componentes (SCA): leitura de manifesto e da resposta do OSV (sem rede)."""

from __future__ import annotations

import pytest

from scanner.sca.manifest import (
    load_manifest_content,
    parse_package_lock,
    parse_requirements,
)
from scanner.sca.models import Component
from scanner.sca.osv import parse_batch_response, parse_vuln


def test_parse_package_lock_v3() -> None:
    data = {
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "projeto"},  # o próprio projeto: ignorado
            "node_modules/lodash": {"version": "4.17.4"},
            "node_modules/express": {"version": "4.18.2"},
        },
    }
    comps = parse_package_lock(data)
    assert Component("npm", "lodash", "4.17.4") in comps
    assert Component("npm", "express", "4.18.2") in comps
    assert all(c.name for c in comps)  # projeto sem nome não entra


def test_parse_requirements() -> None:
    comps = parse_requirements("# comentário\nDjango==3.2.0\nrequests==2.25.1\nsemver>=1.0\n")
    assert Component("PyPI", "Django", "3.2.0") in comps
    assert Component("PyPI", "requests", "2.25.1") in comps
    assert len(comps) == 2  # 'semver>=1.0' não é versão exata: ignorado


def test_load_manifest_content_by_filename() -> None:
    # requirements.txt a partir do conteúdo (sem arquivo em disco)
    comps = load_manifest_content("Django==3.2.0\n", "requirements.txt")
    assert comps == [Component("PyPI", "Django", "3.2.0")]
    # package-lock.json a partir do conteúdo
    lock = '{"lockfileVersion":3,"packages":{"node_modules/lodash":{"version":"4.17.4"}}}'
    assert Component("npm", "lodash", "4.17.4") in load_manifest_content(lock, "package-lock.json")


def test_load_manifest_content_rejects_unknown() -> None:
    with pytest.raises(ValueError, match="não suportado"):
        load_manifest_content("x", "pom.xml")


def test_parse_batch_response_maps_ids_in_order() -> None:
    comps = [Component("npm", "a", "1"), Component("npm", "b", "2"), Component("npm", "c", "3")]
    data = {"results": [{"vulns": [{"id": "X1"}, {"id": "X2"}]}, {}, {"vulns": [{"id": "Y"}]}]}
    out = parse_batch_response(comps, data)
    assert out[comps[0]] == ["X1", "X2"]
    assert comps[1] not in out  # sem falha
    assert out[comps[2]] == ["Y"]


def test_parse_vuln_severity_best_effort() -> None:
    v = parse_vuln({"id": "GHSA-1", "summary": "ReDoS", "database_specific": {"severity": "high"}})
    assert v.id == "GHSA-1" and v.severity == "HIGH" and v.summary == "ReDoS"
    v2 = parse_vuln({"id": "G2", "severity": [{"type": "CVSS_V3", "score": "x"}]})
    assert v2.severity == "CVSS"
