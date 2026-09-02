"""Contract and registry tests for govern audit checks (#5072).

Tests verify:
1. Measured findings without evidence are rejected.
2. not_measurable findings require what_would_make_it_measurable.
3. Raising checks are isolated, reported as not_measurable with the exception
   class name, and do not drop or abort subsequent checks.
4. Check IDs are unique and strictly namespaced.
5. Wrapped producers (doctor adapter and compliance library adapter) yield
   valid findings with canonically hashed evidence.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from bernstein.core.checks.adapters import (
    ComplianceEncryptionAtRestAdapter,
    DoctorComplianceAdapter,
)
from bernstein.core.checks.contract import Evidence, Finding, Verdict
from bernstein.core.checks.registry import CheckRegistry

if TYPE_CHECKING:
    from pathlib import Path


class _DummyCheck:
    """Dummy check implementation for testing."""

    def __init__(self, check_id: str, outcome: Finding | Exception) -> None:
        self._check_id = check_id
        self._outcome = outcome

    @property
    def check_id(self) -> str:
        return self._check_id

    @property
    def title(self) -> str:
        return f"Dummy check {self._check_id}"

    @property
    def description(self) -> str:
        return "A test check for contract verification"

    def run(self, workdir: Path | None = None) -> Finding:
        if isinstance(self._outcome, Exception):
            raise self._outcome
        return self._outcome

    def __call__(self, workdir: Path | None = None) -> Finding:
        return self.run(workdir)


# ---------------------------------------------------------------------------
# 1. Measured finding without evidence is rejected
# ---------------------------------------------------------------------------


def test_measured_finding_without_evidence_is_rejected() -> None:
    """A measured finding (PASS or FAIL) must carry at least one evidence item."""
    # PASS without evidence must raise
    with pytest.raises(ValueError, match="requires at least one evidence item"):
        Finding(
            check_id="test:check_pass",
            verdict=Verdict.PASS,
            evidence=(),
        )

    # FAIL without evidence must raise
    with pytest.raises(ValueError, match="requires at least one evidence item"):
        Finding(
            check_id="test:check_fail",
            verdict=Verdict.FAIL,
            evidence=(),
        )

    # Providing evidence allows creation
    ev = Evidence(locator="test:file", sha256="sha256:abcd1234abcd1234")
    f_pass = Finding(
        check_id="test:check_pass",
        verdict=Verdict.PASS,
        evidence=(ev,),
    )
    assert f_pass.verdict == Verdict.PASS
    assert len(f_pass.evidence) == 1

    f_fail = Finding(
        check_id="test:check_fail",
        verdict=Verdict.FAIL,
        evidence=(ev,),
        remediation="Fix the config",
    )
    assert f_fail.verdict == Verdict.FAIL


# ---------------------------------------------------------------------------
# 2. not_measurable requires what_would_make_it_measurable
# ---------------------------------------------------------------------------


def test_not_measurable_requires_what_would_make_it_measurable() -> None:
    """A not_measurable finding must explain what prerequisite is missing."""
    # None raises ValueError
    with pytest.raises(ValueError, match="requires 'what_would_make_it_measurable'"):
        Finding(
            check_id="test:unmeasurable",
            verdict=Verdict.NOT_MEASURABLE,
            what_would_make_it_measurable=None,
        )

    # Empty string raises ValueError
    with pytest.raises(ValueError, match="requires 'what_would_make_it_measurable'"):
        Finding(
            check_id="test:unmeasurable",
            verdict=Verdict.NOT_MEASURABLE,
            what_would_make_it_measurable="   ",
        )

    # Non-empty explanation succeeds
    finding = Finding(
        check_id="test:unmeasurable",
        verdict=Verdict.NOT_MEASURABLE,
        what_would_make_it_measurable="Set BERNSTEIN_COMPLIANCE=soc2 to enable this check",
    )
    assert finding.verdict == Verdict.NOT_MEASURABLE
    assert finding.what_would_make_it_measurable == "Set BERNSTEIN_COMPLIANCE=soc2 to enable this check"
    assert finding.reason == "Set BERNSTEIN_COMPLIANCE=soc2 to enable this check"


# ---------------------------------------------------------------------------
# 3. Raising check is reported not dropped
# ---------------------------------------------------------------------------


def test_raising_check_is_reported_not_dropped(tmp_path: Path) -> None:
    """A throwing check is reported as not_measurable carrying the exception class."""
    registry = CheckRegistry()

    ev = Evidence(locator="test:mock", sha256="sha256:1111222233334444")
    healthy_finding = Finding(
        check_id="test:healthy",
        verdict=Verdict.PASS,
        evidence=(ev,),
        message="Healthy check passed",
    )

    throwing_check = _DummyCheck(
        check_id="test:thrower",
        outcome=ConnectionResetError("Socket reset by peer"),
    )
    healthy_check = _DummyCheck(
        check_id="test:healthy",
        outcome=healthy_finding,
    )

    registry.register(throwing_check)
    registry.register(healthy_check)

    findings = registry.run_all(tmp_path)

    # Both checks produced findings (none dropped)
    assert len(findings) == 2

    # The throwing check produced exactly one not_measurable finding
    throw_finding = findings[0]
    assert throw_finding.check_id == "test:thrower"
    assert throw_finding.verdict == Verdict.NOT_MEASURABLE
    assert throw_finding.reason == "ConnectionResetError"
    assert "ConnectionResetError" in (throw_finding.what_would_make_it_measurable or "")

    # The second check ran successfully
    healthy_result = findings[1]
    assert healthy_result.check_id == "test:healthy"
    assert healthy_result.verdict == Verdict.PASS
    assert healthy_result.message == "Healthy check passed"


# ---------------------------------------------------------------------------
# 4. Check IDs are unique and namespaced
# ---------------------------------------------------------------------------


def test_ids_are_unique_and_namespaced() -> None:
    """Check IDs must be non-empty, namespaced with colon, and uniquely registered."""
    registry = CheckRegistry()

    ev = Evidence(locator="test:loc", sha256="sha256:aabbccdd")
    finding = Finding(check_id="ns:valid", verdict=Verdict.PASS, evidence=(ev,))

    # Reject un-namespaced IDs
    with pytest.raises(ValueError, match="must be namespaced"):
        registry.register(_DummyCheck("plain_id_without_namespace", finding))

    with pytest.raises(ValueError, match="must be namespaced"):
        registry.register(_DummyCheck(":leading_colon", finding))

    with pytest.raises(ValueError, match="must be namespaced"):
        registry.register(_DummyCheck("trailing_colon:", finding))

    # Registering valid namespaced ID succeeds
    check1 = _DummyCheck("security:rbac_check", finding)
    registry.register(check1)
    assert registry.get_check("security:rbac_check") is check1

    # Registering duplicate ID raises ValueError
    check1_duplicate = _DummyCheck("security:rbac_check", finding)
    with pytest.raises(ValueError, match="already registered"):
        registry.register(check1_duplicate)

    # Registering another distinct namespaced ID succeeds
    check2 = _DummyCheck("doctor:auth_status", finding)
    registry.register(check2)

    registered_ids = [c.check_id for c in registry.iter_checks()]
    assert registered_ids == ["security:rbac_check", "doctor:auth_status"]


# ---------------------------------------------------------------------------
# 5. Two wrapped producers yield valid findings
# ---------------------------------------------------------------------------


def test_two_wrapped_producers_yield_valid_findings(tmp_path: Path) -> None:
    """The two producer adapters yield valid Findings with canonical hashed evidence."""
    # 1. Doctor adapter: DoctorComplianceAdapter
    doctor_adapter = DoctorComplianceAdapter()
    assert doctor_adapter.check_id == "doctor:compliance"
    assert ":" in doctor_adapter.check_id

    # Running in empty workspace -> not_measurable
    doc_finding_unconfigured = doctor_adapter.run(tmp_path)
    assert doc_finding_unconfigured.check_id == "doctor:compliance"
    assert doc_finding_unconfigured.verdict == Verdict.NOT_MEASURABLE
    assert doc_finding_unconfigured.what_would_make_it_measurable is not None

    # Running with compliance config file in .sdd -> PASS or FAIL with valid Evidence
    sdd_config = tmp_path / ".sdd" / "config"
    sdd_config.mkdir(parents=True, exist_ok=True)
    (sdd_config / "compliance.json").write_text('{"preset": "standard"}', encoding="utf-8")

    doc_finding_configured = doctor_adapter.run(tmp_path)
    assert doc_finding_configured.check_id == "doctor:compliance"
    assert doc_finding_configured.verdict in (Verdict.PASS, Verdict.FAIL)
    assert len(doc_finding_configured.evidence) >= 1
    assert doc_finding_configured.evidence[0].sha256.startswith("sha256:")
    assert len(doc_finding_configured.evidence[0].sha256) == 71  # "sha256:" + 64 hex chars

    # 2. Compliance library adapter: ComplianceEncryptionAtRestAdapter
    comp_adapter = ComplianceEncryptionAtRestAdapter()
    assert comp_adapter.check_id == "compliance:soc2:encryption_at_rest"
    assert ":" in comp_adapter.check_id

    # Running against empty directory -> FAIL with evidence
    comp_finding_fail = comp_adapter.run(tmp_path)
    assert comp_finding_fail.check_id == "compliance:soc2:encryption_at_rest"
    assert comp_finding_fail.verdict == Verdict.FAIL
    assert len(comp_finding_fail.evidence) == 1
    assert comp_finding_fail.evidence[0].sha256.startswith("sha256:")
    assert len(comp_finding_fail.evidence[0].sha256) == 71

    # Running against directory with state_encryption configured -> PASS with evidence
    (tmp_path / "bernstein.yaml").write_text("state_encryption: true\n", encoding="utf-8")
    comp_finding_pass = comp_adapter.run(tmp_path)
    assert comp_finding_pass.check_id == "compliance:soc2:encryption_at_rest"
    assert comp_finding_pass.verdict == Verdict.PASS
    assert len(comp_finding_pass.evidence) == 1
    assert comp_finding_pass.evidence[0].sha256.startswith("sha256:")
