"""Perfis de scan e a configuração da política no ZAP.

O cliente `zaproxy` devolve erros como texto: o scanner precisa recusar, não seguir em frente.
"""

from types import SimpleNamespace

import pytest

from scanner.web_scan import policy
from scanner.web_scan.zap import ScanLimits, ZapError, ZapScanner


class FakeAscan:
    def __init__(self, available: set[str]) -> None:
        self.available = available
        self.enabled: set[str] = set()
        self.strengths: dict[str, str] = {}
        self.scan_policy_names: list[str] = []

    def add_scan_policy(self, *a, **kw):
        return "OK"

    def disable_all_scanners(self, **kw):
        self.enabled.clear()
        return "OK"

    def enable_all_scanners(self, **kw):
        self.enabled |= self.available
        return "OK"

    def enable_scanners(self, ids, scanpolicyname):
        wanted = set(ids.split(","))
        if not wanted <= self.available:
            return "does_not_exist"  # comportamento real do ZAP
        self.enabled |= wanted
        return "OK"

    def set_scanner_attack_strength(self, scanner_id, strength, scanpolicyname):
        self.strengths[scanner_id] = strength
        return "OK"

    def scanners(self, name):
        return [{"id": i, "enabled": str(i in self.enabled).lower()} for i in self.available]


def scanner_with(available: set[str]) -> tuple[ZapScanner, FakeAscan]:
    z = ZapScanner.__new__(ZapScanner)
    z.limits = ScanLimits(10, 1, 5)
    ascan = FakeAscan(available)
    z.zap = SimpleNamespace(ascan=ascan)
    return z, ascan


SAFE = policy.PROFILES["safe"]
AGGRESSIVE = policy.PROFILES["aggressive"]


def test_safe_profile_skips_rules_missing_in_this_zap() -> None:
    all_ids = {str(i) for i in policy.SAFE_ACTIVE_RULES}
    z, ascan = scanner_with((all_ids - {"10095"}) | {"30001"})  # 30001 = destrutiva, existe no ZAP
    z.configure_policy(SAFE)
    assert ascan.enabled == all_ids - {"10095"}
    assert "30001" not in ascan.enabled  # destrutiva não entra no perfil seguro


def test_safe_profile_with_no_rules_refuses_scan() -> None:
    z, _ = scanner_with({"30001"})
    with pytest.raises(ZapError):
        z.configure_policy(SAFE)


def test_aggressive_profile_enables_every_rule() -> None:
    z, ascan = scanner_with(
        {str(i) for i in policy.SAFE_ACTIVE_RULES} | {"30001", "40043", "40046"}
    )
    z.configure_policy(AGGRESSIVE)
    # Inclui as destrutivas (30001 overflow, 40043 Log4Shell, 40046 SSRF).
    assert {"30001", "40043", "40046"} <= ascan.enabled
    assert ascan.strengths["30001"] == "HIGH"
