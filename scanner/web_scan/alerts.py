"""Converte alertas do ZAP em candidatos (`Finding` com status `candidate`)."""

from __future__ import annotations

from typing import Any

from scanner.common.evidence import excerpt
from scanner.common.masking import mask_headers, mask_text
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

RISK_TO_SEVERITY = {
    "High": Severity.HIGH,
    "Medium": Severity.MEDIUM,
    "Low": Severity.LOW,
    "Informational": Severity.INFO,
}

BODY_EXCERPT_LIMIT = 2000


def parse_raw_headers(raw: str) -> tuple[str, dict[str, str]]:
    """Separa a primeira linha (request/status line) dos cabeçalhos."""
    lines = [ln for ln in raw.replace("\r\n", "\n").split("\n") if ln.strip()]
    if not lines:
        return "", {}
    headers: dict[str, str] = {}
    for line in lines[1:]:
        name, sep, value = line.partition(":")
        if sep:
            headers[name.strip()] = value.strip()
    return lines[0], headers


def _header(headers: dict[str, str], name: str) -> str | None:
    return next((v for k, v in headers.items() if k.lower() == name), None)


def message_to_evidence(message: dict[str, Any], alert: dict[str, Any]) -> Evidence:
    _, req_headers = parse_raw_headers(message.get("requestHeader", ""))
    status_line, resp_headers = parse_raw_headers(message.get("responseHeader", ""))
    try:
        status = int(status_line.split()[1])
    except (IndexError, ValueError):
        status = 0
    note_parts = [
        f"attack: {alert['attack']}" if alert.get("attack") else "",
        f"evidence: {alert['evidence']}" if alert.get("evidence") else "",
    ]
    return Evidence(
        request=HttpRequest(
            method=alert.get("method", "GET"),
            url=alert["url"],
            headers=mask_headers(req_headers),
            body=mask_text(
                excerpt(
                    message.get("requestBody", ""),
                    _header(req_headers, "content-type"),
                    None,
                    BODY_EXCERPT_LIMIT,
                )
            ),
        ),
        response=HttpResponse(
            status=status,
            headers=mask_headers(resp_headers),
            body_excerpt=mask_text(
                excerpt(
                    message.get("responseBody", ""),
                    _header(resp_headers, "content-type"),
                    alert.get("evidence"),
                    BODY_EXCERPT_LIMIT,
                )
            ),
        ),
        note=mask_text("; ".join(p for p in note_parts if p)) or None,
    )


def alert_to_finding(
    alert: dict[str, Any], message: dict[str, Any] | None, scan_id: str, target_id: str
) -> Finding:
    source = Source(
        tool="zap",
        rule_id=str(alert["pluginId"]),
        rule_name=alert.get("name") or alert.get("alert"),
        tool_severity=alert.get("risk"),
    )
    cwe = int(alert.get("cweid", -1) or -1)
    cwe_or_none = cwe if cwe > 0 else None
    method = (alert.get("method") or "GET").upper()
    param = alert.get("param") or None
    return Finding(
        finding_id=make_finding_id(scan_id, source, method, alert["url"], param),
        scan_id=scan_id,
        target_id=target_id,
        source=source,
        title=source.rule_name or f"ZAP {source.rule_id}",
        description=alert.get("description") or None,
        cwe=cwe_or_none,
        owasp=owasp_for_cwe(cwe_or_none),
        severity=RISK_TO_SEVERITY.get(alert.get("risk", ""), Severity.INFO),
        status=Status.CANDIDATE,
        location=Location(url=alert["url"], method=method, parameter=param),
        evidence=[message_to_evidence(message, alert)] if message else [],
    )
