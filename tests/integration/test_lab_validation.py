"""Provas reais contra o OWASP Juice Shop do docker-compose.lab.yml. Nunca contra sites reais.

docker compose -f docker-compose.yml -f docker-compose.lab.yml --profile test run --rm tests
"""

import os

import pytest

from scanner.common.models import Outcome, Scope
from scanner.common.scope import ScopeGuard
from scanner.validation.http import ProbeClient
from scanner.validation.validators import headers, sqli_error
from tests.conftest import make_finding

pytestmark = pytest.mark.integration

JUICE = os.environ.get("LAB_JUICE_SHOP_URL")
if not JUICE:
    pytest.skip(
        "LAB_JUICE_SHOP_URL não definido (rode via docker-compose.lab.yml)", allow_module_level=True
    )


@pytest.fixture
def client():
    scope = Scope(
        scope_id="lab",
        verified=True,
        locked=True,
        base_urls=[JUICE + "/"],
        allowed_hosts=["juice-shop"],
    )
    c = ProbeClient(ScopeGuard(scope), max_rps=5)
    yield c
    c.close()


def test_juice_shop_search_sqli_is_confirmed(client) -> None:
    f = make_finding(rule_id="40018", cwe=89, url=JUICE + "/rest/products/search?q=apple")
    assert sqli_error.validate(f, client).outcome is Outcome.CONFIRMED


def test_juice_shop_sends_x_frame_options(client) -> None:
    f = make_finding(rule_id="10020", cwe=1021, url=JUICE + "/", param=None)
    assert headers.validate(f, client).outcome is Outcome.FALSE_POSITIVE
