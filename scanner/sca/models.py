"""Modelos do SCA."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Component:
    ecosystem: str  # "npm", "PyPI"
    name: str
    version: str


@dataclass(frozen=True)
class Vuln:
    id: str
    summary: str
    severity: str  # CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN (melhor esforço)
