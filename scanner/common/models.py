"""Modelos do contrato entre etapas.

Espelham `contracts/finding.schema.json` e `contracts/message.schema.json` (fonte da verdade).
`tests/unit/test_contract.py` garante que continuam compatíveis.
"""

from __future__ import annotations

import hashlib
from datetime import datetime
from enum import StrEnum
from typing import Any, Literal
from urllib.parse import urlsplit, urlunsplit

from pydantic import BaseModel, ConfigDict, Field

SCHEMA_VERSION: Literal["1.0"] = "1.0"


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return ["info", "low", "medium", "high", "critical"].index(self.value)


class Status(StrEnum):
    CANDIDATE = "candidate"
    CONFIRMED = "confirmed"
    LIKELY = "likely"
    UNCONFIRMED = "unconfirmed"
    FALSE_POSITIVE = "false_positive"


class Outcome(StrEnum):
    CONFIRMED = "confirmed"
    LIKELY = "likely"
    UNCONFIRMED = "unconfirmed"
    FALSE_POSITIVE = "false_positive"


class Source(_Strict):
    tool: Literal["nuclei", "zap"]
    rule_id: str
    rule_name: str | None = None
    tool_severity: str | None = None


class HttpRequest(_Strict):
    method: str
    url: str
    headers: dict[str, str] = Field(default_factory=dict)
    body: str | None = None


class HttpResponse(_Strict):
    status: int
    headers: dict[str, str] = Field(default_factory=dict)
    body_excerpt: str | None = None


class Evidence(_Strict):
    request: HttpRequest
    response: HttpResponse | None = None
    note: str | None = None


class Validation(_Strict):
    validator: str
    outcome: Outcome
    reason: str
    proof: Evidence | None = None
    validated_at: datetime


class Location(_Strict):
    url: str
    method: str = Field(pattern=r"^[A-Z]+$")
    parameter: str | None = None


class Finding(_Strict):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    finding_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    scan_id: str = Field(min_length=1)
    target_id: str = Field(min_length=1)
    source: Source
    related_sources: list[Source] = Field(default_factory=list)
    title: str = Field(min_length=1)
    description: str | None = None
    cwe: int | None = Field(default=None, ge=1)
    owasp: str | None = Field(default=None, pattern=r"^A(0[1-9]|10):20[0-9]{2}$")
    severity: Severity
    status: Status
    location: Location
    evidence: list[Evidence]
    validation: Validation | None = None

    def dedup_key(self) -> tuple[str, str, str, int | None]:
        """Mesma URL + parâmetro + CWE = mesmo achado, venha do nuclei ou do ZAP."""
        return (
            normalize_url(self.location.url),
            self.location.method,
            self.location.parameter or "",
            self.cwe,
        )


class Scope(_Strict):
    """PROVISÓRIO — formato exato pendente de alinhar com a etapa 1."""

    scope_id: str
    verified: bool
    locked: bool
    base_urls: list[str] = Field(min_length=1)
    allowed_hosts: list[str] = Field(min_length=1)
    include_paths: list[str] = Field(default_factory=list)
    exclude_paths: list[str] = Field(default_factory=list)


Stage = Literal["web.requested", "candidates", "validated", "report.ready"]


class StageMessage(_Strict):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    message_id: str
    scan_id: str = Field(min_length=1)
    target_id: str = Field(min_length=1)
    stage: Stage
    scope: Scope
    payload: dict[str, Any]


def normalize_url(url: str) -> str:
    """Normaliza para comparação: esquema/host minúsculos, sem fragmento, sem porta padrão."""
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    port = parts.port
    if port and not (
        (parts.scheme == "http" and port == 80) or (parts.scheme == "https" and port == 443)
    ):
        host = f"{host}:{port}"
    path = parts.path or "/"
    return urlunsplit((parts.scheme.lower(), host, path, parts.query, ""))


def make_finding_id(
    scan_id: str, source: Source, method: str, url: str, parameter: str | None
) -> str:
    raw = "|".join(
        [scan_id, source.tool, source.rule_id, method.upper(), normalize_url(url), parameter or ""]
    )
    return hashlib.sha256(raw.encode()).hexdigest()
