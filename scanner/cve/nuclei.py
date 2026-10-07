"""Converte eventos JSONL do nuclei em candidatos (`Finding` com status `candidate`)."""

from __future__ import annotations

import json
import re
from typing import Any

from scanner.common.evidence import excerpt
from scanner.common.masking import mask_text
from scanner.common.models import (
    Evidence,
    Finding,
    HttpRequest,
    HttpResponse,
    Location,
    Severity,
    Source,
    Status,
    make_finding_id,
)
from scanner.common.owasp import owasp_for_cwe

# Severidades do nuclei → nossa escala. "unknown" (ou ausente) cai em INFO.
SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "unknown": Severity.INFO,
}

BODY_EXCERPT_LIMIT = 2000

_CWE_RE = re.compile(r"\d+")


def parse_cwe(classification: dict[str, Any] | None) -> int | None:
    """Extrai o primeiro CWE de `classification["cwe-id"]` ("CWE-79" → 79).

    Função pura. Retorna None se ausente ou malformado. Aceita lista ou string.
    """
    if not classification:
        return None
    raw = classification.get("cwe-id")
    if raw is None:
        return None
    if isinstance(raw, list):
        first = raw[0] if raw else None
    else:
        first = raw
    if not isinstance(first, str):
        return None
    match = _CWE_RE.search(first)
    return int(match.group()) if match else None


def _response_status(response: str) -> int:
    """Lê o código de status da primeira linha ("HTTP/1.1 200 OK" → 200)."""
    first_line = response.replace("\r\n", "\n").split("\n", 1)[0]
    parts = first_line.split()
    if len(parts) >= 2:
        try:
            return int(parts[1])
        except ValueError:
            return 0
    return 0


def _event_evidence(event: dict[str, Any], url: str) -> list[Evidence]:
    """Monta uma evidência com a requisição/resposta brutas (mascaradas)."""
    request = event.get("request")
    response = event.get("response")
    if not request and not response:
        return []
    http_response = None
    if response:
        http_response = HttpResponse(
            status=_response_status(response),
            body_excerpt=mask_text(excerpt(response, None, None, BODY_EXCERPT_LIMIT)),
        )
    return [
        Evidence(
            request=HttpRequest(
                method="GET",
                url=url,
                body=mask_text(excerpt(request, None, None, BODY_EXCERPT_LIMIT))
                if request
                else None,
            ),
            response=http_response,
            note=mask_text(f"matched-at: {event['matched-at']}")
            if event.get("matched-at")
            else None,
        )
    ]


def nuclei_to_finding(event: dict[str, Any], scan_id: str, target_id: str) -> Finding:
    """Mapeia um evento JSONL do nuclei para um `Finding`. Função pura."""
    info: dict[str, Any] = event.get("info") or {}
    classification = info.get("classification")
    cwe = parse_cwe(classification)
    source = Source(
        tool="nuclei",
        rule_id=str(event["template-id"]),
        rule_name=info.get("name"),
        tool_severity=info.get("severity"),
    )
    method = "GET"
    url = event.get("matched-at") or event.get("host") or ""
    severity = SEVERITY_MAP.get((info.get("severity") or "").lower(), Severity.INFO)
    return Finding(
        finding_id=make_finding_id(scan_id, source, method, url, None),
        scan_id=scan_id,
        target_id=target_id,
        source=source,
        title=source.rule_name or f"nuclei {source.rule_id}",
        description=info.get("description") or None,
        cwe=cwe,
        owasp=owasp_for_cwe(cwe),
        severity=severity,
        status=Status.CANDIDATE,
        location=Location(url=url, method=method),
        evidence=_event_evidence(event, url),
    )


def parse_nuclei_jsonl(text: str, scan_id: str, target_id: str) -> list[Finding]:
    """Converte a saída `-jsonl` do nuclei. Um `Finding` por linha válida. Função pura.

    Linhas em branco ou malformadas (JSON inválido ou sem `template-id`) são ignoradas.
    """
    findings: list[Finding] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(event, dict) or not event.get("template-id"):
            continue
        findings.append(nuclei_to_finding(event, scan_id, target_id))
    return findings


def build_nuclei_command(target_url: str) -> list[str]:
    """Argv do nuclei headless com saída JSONL contra um único alvo. Função pura."""
    return [
        "nuclei",
        "-u",
        target_url,
        "-jsonl",
        "-silent",
        "-disable-update-check",
    ]
