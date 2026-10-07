import re

import pytest

from scanner.common.scope import OutOfScopeError, ScopeGuard


def test_allows_only_scope_hosts(scope) -> None:
    g = ScopeGuard(scope)
    assert g.allows("http://juice-shop:3000/rest/products")
    assert not g.allows("http://evil.example/")
    assert not g.allows("http://juice-shop.evil.example/")
    assert not g.allows("ftp://juice-shop/")


def test_exclude_paths(scope) -> None:
    g = ScopeGuard(scope)
    assert not g.allows("http://juice-shop:3000/logout")
    with pytest.raises(OutOfScopeError):
        g.require("http://juice-shop:3000/logout")


def test_zap_regexes(scope) -> None:
    g = ScopeGuard(scope)
    [inc] = g.zap_include_regexes()
    assert re.fullmatch(inc, "http://juice-shop:3000/a/b")
    assert not re.fullmatch(inc, "http://juice-shop.evil.example/")
    [exc] = g.zap_exclude_regexes()
    assert re.fullmatch(exc, "http://juice-shop:3000/logout")
