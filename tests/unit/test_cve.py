from scanner.common.models import Severity, Status
from scanner.cve.nuclei import nuclei_to_finding, parse_cwe, parse_nuclei_jsonl

EVENT = {
    "template-id": "CVE-2021-1234",
    "info": {
        "name": "Some Vuln",
        "severity": "high",
        "description": "desc",
        "classification": {"cwe-id": ["CWE-79"], "cve-id": ["CVE-2021-1234"]},
    },
    "type": "http",
    "host": "http://juice-shop:3000",
    "matched-at": "http://juice-shop:3000/path?x=1",
    "request": "GET /path?x=1 HTTP/1.1\r\nHost: juice-shop:3000\r\n\r\n",
    "response": "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>ok</html>",
}


def test_parse_cwe_extracts_integer() -> None:
    assert parse_cwe({"cwe-id": ["CWE-79"]}) == 79
    assert parse_cwe({"cwe-id": "CWE-89"}) == 89


def test_parse_cwe_missing_or_malformed() -> None:
    assert parse_cwe(None) is None
    assert parse_cwe({}) is None
    assert parse_cwe({"cwe-id": []}) is None
    assert parse_cwe({"cwe-id": ["sem-numero"]}) is None
    assert parse_cwe({"cwe-id": [None]}) is None


def test_nuclei_event_becomes_candidate() -> None:
    f = nuclei_to_finding(EVENT, "scan-1", "target-1")
    assert f.source.tool == "nuclei"
    assert f.source.rule_id == "CVE-2021-1234"
    assert f.source.rule_name == "Some Vuln"
    assert f.source.tool_severity == "high"
    assert f.status is Status.CANDIDATE
    assert f.severity is Severity.HIGH
    assert f.cwe == 79 and f.owasp == "A05:2025"
    assert f.location.url == "http://juice-shop:3000/path?x=1"
    assert f.location.method == "GET"
    [ev] = f.evidence
    assert ev.request.url == "http://juice-shop:3000/path?x=1"
    assert ev.response is not None and ev.response.status == 200
    # Finding serializa no formato do contrato.
    assert f.model_dump(mode="json")["source"]["tool"] == "nuclei"


def test_finding_id_is_deterministic() -> None:
    a = nuclei_to_finding(EVENT, "scan-1", "target-1")
    b = nuclei_to_finding(EVENT, "scan-1", "target-1")
    assert a.finding_id == b.finding_id


def test_unknown_severity_defaults_to_info() -> None:
    event = EVENT | {"info": {"name": "x", "severity": "unknown"}}
    assert nuclei_to_finding(event, "scan-1", "target-1").severity is Severity.INFO


def test_missing_cwe_has_no_owasp() -> None:
    event = EVENT | {"info": {"name": "x", "severity": "low"}}
    f = nuclei_to_finding(event, "scan-1", "target-1")
    assert f.cwe is None and f.owasp is None


def test_falls_back_to_host_when_no_match() -> None:
    event = {k: v for k, v in EVENT.items() if k != "matched-at"}
    f = nuclei_to_finding(event, "scan-1", "target-1")
    assert f.location.url == "http://juice-shop:3000"


def test_parse_jsonl_skips_blank_and_malformed() -> None:
    import json

    text = "\n".join(
        [
            json.dumps(EVENT),
            "",
            "   ",
            "{not valid json",
            json.dumps({"info": {"name": "sem id"}}),  # sem template-id
            json.dumps(EVENT | {"template-id": "CVE-2022-9999"}),
        ]
    )
    findings = parse_nuclei_jsonl(text, "scan-1", "target-1")
    assert len(findings) == 2
    assert {f.source.rule_id for f in findings} == {"CVE-2021-1234", "CVE-2022-9999"}
