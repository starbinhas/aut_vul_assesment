from __future__ import annotations

from typing import Any

import httpx
import pytest

from scanner.common.models import (
    Evidence,
    Finding,
    HttpRequest,
    HttpResponse,
    Location,
    Scope,
    Severity,
    Source,
    Status,
    make_finding_id,
)
from scanner.validation.http import ProbeResponse

LAB_URL = "http://juice-shop:3000"


@pytest.fixture
def scope() -> Scope:
    return Scope(
        scope_id="scope-1",
        verified=True,
        locked=True,
        base_urls=[LAB_URL + "/"],
        allowed_hosts=["juice-shop"],
        exclude_paths=[r"^/logout"],
    )


def make_finding(
    *,
    tool: str = "zap",
    rule_id: str = "40012",
    url: str = LAB_URL + "/search?q=abc",
    method: str = "GET",
    param: str | None = "q",
    cwe: int | None = 79,
    severity: Severity = Severity.MEDIUM,
    status: Status = Status.CANDIDATE,
    **kw: Any,
) -> Finding:
    source = Source(tool=tool, rule_id=rule_id, rule_name=f"{tool} {rule_id}")  # type: ignore[arg-type]
    return Finding(
        finding_id=make_finding_id("scan-1", source, method, url, param),
        scan_id="scan-1",
        target_id="target-1",
        source=source,
        title=kw.pop("title", "Cross Site Scripting (Reflected)"),
        cwe=cwe,
        severity=severity,
        status=status,
        location=Location(url=url, method=method, parameter=param),
        evidence=kw.pop(
            "evidence",
            [
                Evidence(
                    request=HttpRequest(method=method, url=url, headers={"Cookie": "***"}),
                    response=HttpResponse(
                        status=200, headers={"Server": "nginx"}, body_excerpt="ok"
                    ),
                )
            ],
        ),
        **kw,
    )


class FakeClient:
    """ProbeClient falso: responde com uma função (url -> ProbeResponse) e registra as chamadas."""

    def __init__(self, responder: Any) -> None:
        self.responder = responder
        self.calls: list[tuple[str, str]] = []

    def request(
        self, method: str, url: str, headers: dict[str, str] | None = None
    ) -> ProbeResponse:
        self.calls.append((method, url))
        return self.responder(url)


def resp(
    text: str = "",
    status: int = 200,
    headers: dict[str, str] | None = None,
    set_cookies: list[str] | None = None,
) -> ProbeResponse:
    h = httpx.Headers({"content-type": "text/html; charset=utf-8", **(headers or {})})
    return ProbeResponse(status=status, headers=h, text=text, url="", set_cookies=set_cookies or [])
