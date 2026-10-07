import httpx
import pytest
import respx

from scanner.common.scope import OutOfScopeError, ScopeGuard
from scanner.validation.http import ProbeClient, UnsafeRequestError


@respx.mock
def test_does_not_follow_redirects(scope) -> None:
    respx.get("http://juice-shop:3000/r").mock(
        return_value=httpx.Response(302, headers={"Location": "http://evil.example/"})
    )
    client = ProbeClient(ScopeGuard(scope), max_rps=50)
    r = client.request("GET", "http://juice-shop:3000/r")
    assert r.status == 302


def test_blocks_out_of_scope_and_unsafe_methods(scope) -> None:
    client = ProbeClient(ScopeGuard(scope), max_rps=50)
    with pytest.raises(OutOfScopeError):
        client.request("GET", "http://evil.example/")
    with pytest.raises(UnsafeRequestError):
        client.request("DELETE", "http://juice-shop:3000/api/x")
    with pytest.raises(UnsafeRequestError):
        client.request("POST", "http://juice-shop:3000/api/x")
