from scanner.common.models import Severity, Status
from scanner.web_scan.alerts import alert_to_finding

ALERT = {
    "pluginId": "40012",
    "name": "Cross Site Scripting (Reflected)",
    "risk": "High",
    "url": "http://juice-shop:3000/search?q=x",
    "method": "GET",
    "param": "q",
    "cweid": "79",
    "attack": "<script>alert(1)</script>",
    "evidence": "<script>alert(1)</script>",
    "description": "desc",
    "messageId": "12",
}

MESSAGE = {
    "requestHeader": "GET /search?q=x HTTP/1.1\r\nHost: juice-shop:3000\r\nCookie: token=abc\r\n\r\n",
    "requestBody": "",
    "responseHeader": "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nSet-Cookie: sid=1\r\n\r\n",
    "responseBody": "<html>... <script>alert(1)</script> ...</html>",
}


def test_alert_becomes_candidate() -> None:
    f = alert_to_finding(ALERT, MESSAGE, "scan-1", "target-1")
    assert f.status is Status.CANDIDATE
    assert f.severity is Severity.HIGH
    assert f.cwe == 79 and f.owasp == "A05:2025"
    [ev] = f.evidence
    assert ev.response is not None and ev.response.status == 200
    assert ev.request.headers["Cookie"] == "***"
    assert ev.response.headers["Set-Cookie"] == "***"


def test_finding_id_is_deterministic() -> None:
    a = alert_to_finding(ALERT, MESSAGE, "scan-1", "target-1")
    b = alert_to_finding(ALERT, None, "scan-1", "target-1")
    assert a.finding_id == b.finding_id


def test_unknown_cwe_is_none() -> None:
    f = alert_to_finding(ALERT | {"cweid": "-1"}, None, "scan-1", "target-1")
    assert f.cwe is None and f.owasp is None


def test_binary_body_is_not_stored() -> None:
    message = MESSAGE | {
        "responseHeader": "HTTP/1.1 200 OK\r\nContent-Type: font/woff\r\n\r\n",
        "responseBody": "wOFF\x00\x01\x00\x00binário",
    }
    [ev] = alert_to_finding(ALERT, message, "scan-1", "target-1").evidence
    assert ev.response is not None and ev.response.body_excerpt is None


def test_null_char_is_removed_from_text() -> None:
    message = MESSAGE | {"responseBody": "<html>" + "a" * 2000 + "\x00x</html>"}
    [ev] = alert_to_finding(ALERT, message, "scan-1", "target-1").evidence
    assert ev.response is not None and "\x00" not in (ev.response.body_excerpt or "")


def test_strip_nul_nested() -> None:
    from scanner.common.evidence import strip_nul

    assert strip_nul({"a": ["x\x00y", {"b": "\x00"}], "n": 1}) == {"a": ["xy", {"b": ""}], "n": 1}
