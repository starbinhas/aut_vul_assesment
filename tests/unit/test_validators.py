from urllib.parse import parse_qs, urlsplit

import httpx

from scanner.common.models import Outcome, Severity, Status
from scanner.validation.service import validate_one
from scanner.validation.validators import (
    cookies,
    headers,
    open_redirect,
    path_traversal,
    select,
    sqli_error,
    ssti,
    xss_reflected,
)
from tests.conftest import LAB_URL, FakeClient, make_finding, resp


def q(url: str) -> str:
    return parse_qs(urlsplit(url).query)["q"][0]


def q_named(url: str, name: str) -> str:
    return parse_qs(urlsplit(url).query)[name][0]


# --- XSS ---------------------------------------------------------------------------------


def test_xss_confirmed_when_marker_reflected_raw() -> None:
    client = FakeClient(lambda url: resp(f"<p>Resultados para {q(url)}</p>"))
    v = xss_reflected.validate(make_finding(), client)
    assert v.outcome is Outcome.CONFIRMED
    assert v.proof is not None


def test_xss_escaped_is_unconfirmed_never_false_positive() -> None:
    import html

    client = FakeClient(lambda url: resp(f"<p>{html.escape(q(url))}</p>"))
    v = xss_reflected.validate(make_finding(), client)
    assert v.outcome is Outcome.UNCONFIRMED


def test_xss_post_is_not_replayed() -> None:
    client = FakeClient(lambda url: resp())
    v = xss_reflected.validate(make_finding(method="POST"), client)
    assert v.outcome is Outcome.UNCONFIRMED and client.calls == []


# --- SQLi --------------------------------------------------------------------------------


def test_sqli_error_confirmed() -> None:
    def responder(url: str):
        value = q(url)
        if value.endswith("'") and not value.endswith("''"):
            return resp('SQLITE_ERROR: near "\'": syntax error')
        return resp("[]")

    f = make_finding(rule_id="40018", cwe=89, url=LAB_URL + "/rest/products/search?q=x")
    v = sqli_error.validate(f, FakeClient(responder))
    assert v.outcome is Outcome.CONFIRMED


def test_sqli_no_error_is_unconfirmed() -> None:
    f = make_finding(rule_id="40018", cwe=89)
    v = sqli_error.validate(f, FakeClient(lambda url: resp("[]")))
    assert v.outcome is Outcome.UNCONFIRMED


def test_sqli_boolean_confirmed_when_true_keeps_and_false_changes() -> None:
    long_body = "<table>" + "<tr>linha</tr>" * 60 + "</table>"

    def responder(url: str):
        value = q(url)
        if "='2" in value:  # condição FALSA -> resposta alterada (vazia)
            return resp("")
        return resp(long_body)  # original/verdadeira -> resposta preservada; sem erro de banco

    f = make_finding(rule_id="40018", cwe=89, url=LAB_URL + "/rest/products/search?q=abc")
    v = sqli_error.validate(f, FakeClient(responder))
    assert v.outcome is Outcome.CONFIRMED and v.proof is not None


def test_sqli_boolean_unconfirmed_when_no_difference() -> None:
    # Verdadeira e falsa dão a mesma resposta -> sem sinal -> não confirma (evita falso positivo).
    f = make_finding(rule_id="40018", cwe=89)
    v = sqli_error.validate(f, FakeClient(lambda url: resp("<p>estável</p>")))
    assert v.outcome is Outcome.UNCONFIRMED


def test_sqli_never_sends_destructive_payloads() -> None:
    client = FakeClient(lambda url: resp("[]"))
    sqli_error.validate(make_finding(rule_id="40018", cwe=89), client)
    for _, url in client.calls:
        value = q(url).upper()
        assert not any(
            k in value for k in ("OR ", "UNION", ";", "DROP", "DELETE", "UPDATE", "SLEEP")
        )


# --- cabeçalhos e cookies ----------------------------------------------------------------


def test_header_present_is_false_positive() -> None:
    f = make_finding(rule_id="10020", cwe=1021, param=None)
    v = headers.validate(f, FakeClient(lambda url: resp(headers={"X-Frame-Options": "SAMEORIGIN"})))
    assert v.outcome is Outcome.FALSE_POSITIVE


def test_header_missing_is_confirmed() -> None:
    f = make_finding(rule_id="10021", cwe=693, param=None)
    v = headers.validate(f, FakeClient(lambda url: resp()))
    assert v.outcome is Outcome.CONFIRMED


def test_cookie_without_httponly_confirmed() -> None:
    f = make_finding(rule_id="10010", cwe=1004, param="sid")
    client = FakeClient(lambda url: resp(set_cookies=["sid=1; Path=/; Secure"]))
    assert cookies.validate(f, client).outcome is Outcome.CONFIRMED


def test_cookie_with_flag_false_positive() -> None:
    f = make_finding(rule_id="10010", cwe=1004, param="sid")
    client = FakeClient(lambda url: resp(set_cookies=["sid=1; Path=/; HttpOnly"]))
    assert cookies.validate(f, client).outcome is Outcome.FALSE_POSITIVE


# --- seleção e orquestração --------------------------------------------------------------


def test_select_by_nuclei_falls_back_to_cwe() -> None:
    v = select(make_finding(tool="nuclei", rule_id="some-template", cwe=89))
    assert v is not None and v.name == "sqli_error"


def test_unknown_family_is_unconfirmed() -> None:
    f = validate_one(make_finding(rule_id="99999", cwe=None), FakeClient(lambda url: resp()))
    assert f.status is Status.UNCONFIRMED


def test_validator_crash_is_unconfirmed() -> None:
    def boom(url: str):
        raise RuntimeError("timeout")

    f = validate_one(make_finding(), FakeClient(boom))
    assert f.status is Status.UNCONFIRMED


def test_unreachable_target_says_so() -> None:
    def refused(url: str):
        raise httpx.ConnectError("[Errno 111] Connection refused")

    f = validate_one(make_finding(), FakeClient(refused))
    assert f.status is Status.UNCONFIRMED
    assert f.validation is not None and "não respondeu" in f.validation.reason


def test_confirmed_gets_base_severity() -> None:
    f = make_finding(rule_id="40018", cwe=89, severity=Severity.MEDIUM)
    client = FakeClient(lambda url: resp("SQLITE_ERROR" if q(url) == "1'" else "[]"))
    out = validate_one(f, client)
    assert out.status is Status.CONFIRMED and out.severity is Severity.HIGH


# --- open redirect -----------------------------------------------------------------------


def _redir_finding(**kw):
    return make_finding(
        rule_id="20019", cwe=601, url=LAB_URL + "/redirect?to=home", param="to", **kw
    )


def test_open_redirect_confirmed_when_location_is_injected_host() -> None:
    def responder(url: str):
        dest = parse_qs(urlsplit(url).query)["to"][0]  # o alvo ecoa o parâmetro no Location
        return resp(status=302, headers={"location": dest})

    v = open_redirect.validate(_redir_finding(), FakeClient(responder))
    assert v.outcome is Outcome.CONFIRMED and v.proof is not None


def test_open_redirect_same_site_is_unconfirmed() -> None:
    client = FakeClient(lambda url: resp(status=302, headers={"location": "/home"}))
    v = open_redirect.validate(_redir_finding(), client)
    assert v.outcome is Outcome.UNCONFIRMED


def test_open_redirect_no_redirect_is_unconfirmed() -> None:
    client = FakeClient(lambda url: resp(status=200))
    v = open_redirect.validate(_redir_finding(), client)
    assert v.outcome is Outcome.UNCONFIRMED


def test_open_redirect_protocol_relative_is_confirmed() -> None:
    def responder(url: str):
        host = parse_qs(urlsplit(url).query)["to"][0].split("://")[1].rstrip("/")
        return resp(status=301, headers={"location": f"//{host}/phish"})

    v = open_redirect.validate(_redir_finding(), FakeClient(responder))
    assert v.outcome is Outcome.CONFIRMED


def test_open_redirect_post_is_not_replayed() -> None:
    client = FakeClient(lambda url: resp(status=302, headers={"location": "x"}))
    v = open_redirect.validate(_redir_finding(method="POST"), client)
    assert v.outcome is Outcome.UNCONFIRMED and client.calls == []


# --- path traversal ----------------------------------------------------------------------


def _pt_finding(**kw):
    return make_finding(
        rule_id="6", cwe=22, url=LAB_URL + "/download?file=report.pdf", param="file", **kw
    )


def test_path_traversal_confirmed_when_passwd_returned() -> None:
    def responder(url: str):
        value = q_named(url, "file")
        if "etc/passwd" in value or "etc%2fpasswd" in value.lower():
            return resp("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:")
        return resp("conteúdo normal")

    v = path_traversal.validate(_pt_finding(), FakeClient(responder))
    assert v.outcome is Outcome.CONFIRMED and v.proof is not None


def test_path_traversal_unconfirmed_when_no_system_file() -> None:
    v = path_traversal.validate(_pt_finding(), FakeClient(lambda url: resp("nada aqui")))
    assert v.outcome is Outcome.UNCONFIRMED


def test_path_traversal_post_is_not_replayed() -> None:
    client = FakeClient(lambda url: resp("root:x:0:0:"))
    v = path_traversal.validate(_pt_finding(method="POST"), client)
    assert v.outcome is Outcome.UNCONFIRMED and client.calls == []


# --- SSTI ---------------------------------------------------------------------------------


def _ssti_finding(**kw):
    return make_finding(
        rule_id="90035", cwe=1336, url=LAB_URL + "/greet?name=joe", param="name", **kw
    )


def test_ssti_confirmed_when_expression_is_evaluated() -> None:
    # Servidor vulnerável: avalia o template e devolve o produto (sem ecoar a expressão crua).
    def responder(url: str):
        value = q_named(url, "name")
        if "12*13" in value:
            return resp("Olá, 156!")
        return resp("Olá!")

    v = ssti.validate(_ssti_finding(), FakeClient(responder), numbers=(12, 13))
    assert v.outcome is Outcome.CONFIRMED and v.proof is not None


def test_ssti_unconfirmed_when_only_reflected() -> None:
    # Servidor seguro: reflete a expressão crua, sem avaliar -> produto ausente -> não confirma.
    def responder(url: str):
        return resp(f"Olá, {q_named(url, 'name')}!")

    v = ssti.validate(_ssti_finding(), FakeClient(responder), numbers=(12, 13))
    assert v.outcome is Outcome.UNCONFIRMED


def test_ssti_post_is_not_replayed() -> None:
    client = FakeClient(lambda url: resp("156"))
    v = ssti.validate(_ssti_finding(method="POST"), client, numbers=(12, 13))
    assert v.outcome is Outcome.UNCONFIRMED and client.calls == []
