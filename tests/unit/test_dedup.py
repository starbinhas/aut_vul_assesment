from scanner.common.models import Severity
from scanner.validation.dedup import deduplicate
from tests.conftest import make_finding


def test_same_url_param_cwe_from_zap_and_nuclei_becomes_one() -> None:
    zap = make_finding(tool="zap", rule_id="40012")
    nuclei = make_finding(tool="nuclei", rule_id="reflected-xss", severity=Severity.HIGH)
    new, updated = deduplicate([zap, nuclei])
    assert updated == []
    [f] = new
    assert f.finding_id == zap.finding_id
    assert [s.tool for s in f.related_sources] == ["nuclei"]
    assert f.severity is Severity.HIGH


def test_different_params_stay_separate() -> None:
    new, _ = deduplicate([make_finding(param="q"), make_finding(param="id")])
    assert len(new) == 2


def test_redelivery_is_idempotent() -> None:
    f = make_finding()
    new, updated = deduplicate([f], existing=[f])
    assert new == [] and updated == []


def test_merge_into_existing() -> None:
    existing = make_finding(tool="nuclei", rule_id="reflected-xss")
    new, updated = deduplicate([make_finding(tool="zap")], existing=[existing])
    assert new == []
    [u] = updated
    assert u.finding_id == existing.finding_id
    assert u.related_sources[0].tool == "zap"


def test_without_cwe_only_merges_same_rule() -> None:
    a = make_finding(cwe=None, rule_id="1")
    b = make_finding(cwe=None, rule_id="2")
    new, _ = deduplicate([a, b])
    assert len(new) == 2
