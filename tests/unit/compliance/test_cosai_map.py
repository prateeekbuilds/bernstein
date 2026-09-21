"""Unit tests for the CoSAI evidence-pack control map (Issue #5945).

Covers:
* Registration: ``cosai`` is in ``SUPPORTED_STANDARDS`` and resolves via
  ``get_standard_map``.
* Shape: every control carries the required keys and a valid status.
* Completeness: every mapped control resolves to exactly one of ``mapped``
  / ``partial`` / ``todo`` and status counts sum to ``len(CONTROLS)``.
* Honesty: at least one control is marked ``"partial"`` and at least one
  is marked ``"todo"`` (the map is not all-green).
* Grounding: every ``selector`` event-type token cited by the map is a
  literal ``event_type`` string emitted or referenced in the Bernstein source tree.
* End-to-end: ``build_evidence_pack`` produces a well-formed pack for
  ``cosai`` whose ``controls.json`` matches the map and whose manifest
  counts match the actual status distribution.
* Docs path integrity: ``test_cosai_mapping_paths_exist_and_exercise_modules``
  parses ``docs/compliance/cosai-mapping.md`` and validates that every cited
  module and test file exists on disk and that each exercising test
  actually references its corresponding implementation module.
"""

from __future__ import annotations

import hashlib
import json
import re
import zipfile
from collections import Counter
from pathlib import Path

import pytest

from bernstein.compliance import cosai
from bernstein.compliance.evidence_pack import (
    SUPPORTED_STANDARDS,
    build_evidence_pack,
    get_standard_map,
)

pytestmark = pytest.mark.whole_tree_guard

# Selector tokens that are legitimate evidence but are not themselves
# ``event_type`` literals (lineage / cost-ledger fields or the "n/a" placeholder).
_NON_EVENT_SELECTOR_TOKENS: frozenset[str] = frozenset(
    {
        "content_hash",
        "parent_hashes",
        "model",
        "task_id",
        "usd",
        "n/a",
    }
)

_VALID_STATUSES: frozenset[str] = frozenset({"mapped", "partial", "todo"})


def _source_event_types() -> set[str]:
    """Collect every literal ``event_type`` string actively used in the codebase.

    Scans for direct ``event_type="..."`` call sites as well as ``*_EVENT_* = "..."``
    and ``EVENT_* = "..."`` constant definitions that are referenced in the codebase.
    """
    repo_root = Path(__file__).resolve().parents[3]
    src_root = repo_root / "src" / "bernstein"
    tests_root = repo_root / "tests"
    assert src_root.is_dir(), src_root

    call_pat = re.compile(r'event_type\s*=\s*["\']([a-z0-9_.]+)["\']')
    const_pat = re.compile(r'\b([A-Z0-9_]*EVENT[A-Z0-9_]*)\s*=\s*["\']([a-z0-9_.]+)["\']')
    word_pat = re.compile(r"\b[A-Z0-9_]+\b")

    word_counts: Counter[str] = Counter()
    call_events: set[str] = set()
    constants: dict[str, str] = {}

    all_paths = list(src_root.rglob("*.py")) + list(tests_root.rglob("*.py"))
    for path in all_paths:
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        call_events.update(call_pat.findall(text))
        for cname, cval in const_pat.findall(text):
            constants[cname] = cval
        for w in word_pat.findall(text):
            word_counts[w] += 1

    active_const_events = {cval for cname, cval in constants.items() if word_counts[cname] >= 2}
    return call_events | active_const_events


@pytest.fixture(scope="module")
def source_event_types() -> set[str]:
    return _source_event_types()


def test_standard_is_registered() -> None:
    assert "cosai" in SUPPORTED_STANDARDS
    mapping = get_standard_map("cosai")
    assert mapping["regulation"]
    assert mapping["controls"]


def test_every_control_has_required_keys_and_valid_status() -> None:
    mapping = get_standard_map("cosai")
    for control in mapping["controls"]:
        for key in ("control_id", "requirement", "artefact", "selector", "status"):
            assert key in control, (control.get("control_id"), key)
            assert control[key] != "", (control.get("control_id"), key)
        assert control["status"] in _VALID_STATUSES, control


def test_every_cosai_control_is_counted_exactly_once() -> None:
    mapping = get_standard_map("cosai")
    controls = mapping["controls"]
    counted = sum(1 for c in controls if c["status"] in _VALID_STATUSES)
    assert counted == len(controls)

    statuses = [c["status"] for c in controls]
    mapped = statuses.count("mapped")
    partial = statuses.count("partial")
    todo = statuses.count("todo")
    assert mapped + partial + todo == len(controls)
    assert mapped == 10
    assert partial == 2
    assert todo == 1


def test_map_honesty_declares_partial_and_todo() -> None:
    mapping = get_standard_map("cosai")
    statuses = {c["control_id"]: c["status"] for c in mapping["controls"]}
    assert "partial" in statuses.values(), statuses
    assert "todo" in statuses.values(), statuses


def test_todo_controls_carry_no_chain_selector() -> None:
    mapping = get_standard_map("cosai")
    for control in mapping["controls"]:
        if control["status"] == "todo":
            assert control["selector"] == "n/a", control
            assert control["artefact"] == "n/a", control


def test_selectors_reference_real_event_types(source_event_types: set[str]) -> None:
    mapping = get_standard_map("cosai")
    unknown: list[tuple[str, str]] = []
    for control in mapping["controls"]:
        for token in str(control["selector"]).split(","):
            token = token.strip()
            if not token or token in _NON_EVENT_SELECTOR_TOKENS:
                continue
            if token not in source_event_types:
                unknown.append((control["control_id"], token))
    assert not unknown, f"cosai cites event types not found in src: {unknown}"


def test_control_map_returns_copy() -> None:
    first = cosai.control_map()
    first["controls"][0]["status"] = "MUTATED"
    second = cosai.control_map()
    assert second["controls"][0]["status"] != "MUTATED"


# ---------------------------------------------------------------------------
# End-to-end pack build
# ---------------------------------------------------------------------------


def _seed_sdd(tmp_path: Path) -> Path:
    sdd = tmp_path / ".sdd"
    audit = sdd / "audit"
    audit.mkdir(parents=True)
    (audit / "log.jsonl").write_text(
        json.dumps(
            {
                "timestamp": "2026-01-05T10:00:00+00:00",
                "event_type": "task.transition",
                "actor": "agent",
                "resource_type": "task",
                "resource_id": "T-1",
                "hmac": "a" * 64,
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return sdd


def test_build_evidence_pack_wellformed(tmp_path: Path) -> None:
    sdd = _seed_sdd(tmp_path)
    out = tmp_path / "pack.zip"
    pack = build_evidence_pack(
        sdd_dir=sdd,
        standard="cosai",
        output_path=out,
        write=True,
    )
    assert pack.standard == "cosai"
    assert pack.event_count == 1

    mapping = get_standard_map("cosai")
    n_controls = len(mapping["controls"])
    assert (
        pack.controls_mapped + pack.controls_partial + pack.controls_organisational + pack.controls_todo == n_controls
    )
    assert pack.controls_mapped == 10
    assert pack.controls_partial == 2
    assert pack.controls_todo == 1
    assert out.is_file()

    with zipfile.ZipFile(out) as zf:
        names = set(zf.namelist())
        for required in (
            "manifest.json",
            "controls.json",
            "audit-chain/events.jsonl",
            "lineage/log.jsonl",
            "costs/cost_history.jsonl",
            "README.md",
        ):
            assert required in names, required

        controls = json.loads(zf.read("controls.json"))
        assert controls["standard"] == "cosai"
        assert len(controls["controls"]) == n_controls

        manifest = json.loads(zf.read("manifest.json"))
        assert manifest["controls_mapped"] == pack.controls_mapped
        assert manifest["controls_partial"] == pack.controls_partial
        assert manifest["controls_todo"] == pack.controls_todo
        assert pack.to_dict()["controls_todo"] == pack.controls_todo
        for name, digest in manifest["artefacts"].items():
            if name == "manifest.json":
                continue
            assert hashlib.sha256(zf.read(name)).hexdigest() == digest, name


def test_build_evidence_pack_is_deterministic(tmp_path: Path) -> None:
    sdd = _seed_sdd(tmp_path)
    a = build_evidence_pack(sdd_dir=sdd, standard="cosai", output_path=tmp_path / "a.zip")
    b = build_evidence_pack(sdd_dir=sdd, standard="cosai", output_path=tmp_path / "b.zip")
    assert a.sha256 == b.sha256
    assert (tmp_path / "a.zip").read_bytes() == (tmp_path / "b.zip").read_bytes()


def test_cosai_mapping_paths_exist_and_exercise_modules() -> None:
    """Every module and test path cited in docs/compliance/cosai-mapping.md must exist,

    and each cited exercising test must actually reference/import the cited module.
    """
    repo_root = Path(__file__).resolve().parents[3]
    doc_path = repo_root / "docs" / "compliance" / "cosai-mapping.md"
    assert doc_path.is_file(), f"Missing docs file: {doc_path}"

    text = doc_path.read_text(encoding="utf-8")

    # Match rows whose first column is a sub-clause ID under one of the three principles
    control_prefixes = ("human-governed-accountable.", "bounded-resilient.", "transparent-verifiable.")
    rows: list[list[str]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("|") or not line.endswith("|"):
            continue
        cells = [c.strip().strip("`") for c in line.strip("|").split("|")]
        if len(cells) >= 5 and any(cells[0].startswith(p) for p in control_prefixes):
            rows.append(cells)

    assert len(rows) == 13, f"Expected 13 control rows in cosai-mapping.md, found {len(rows)}"

    missing_paths: list[str] = []
    unrelated_tests: list[tuple[str, str, str]] = []

    for cells in rows:
        ctrl_id = cells[0]
        mod_path = cells[3]
        test_path = cells[4]
        if mod_path == "n/a" or test_path == "n/a":
            continue

        full_mod = repo_root / mod_path
        full_test = repo_root / test_path

        if not full_mod.exists():
            missing_paths.append(mod_path)
        if not full_test.exists():
            missing_paths.append(test_path)

        if full_mod.exists() and full_test.exists():
            test_content = full_test.read_text(encoding="utf-8")
            mod_stem = full_mod.stem
            mod_import = mod_path.replace("src/", "").replace(".py", "").replace("/", ".")
            # The test must reference the module name or import path
            if mod_stem not in test_content and mod_import not in test_content:
                unrelated_tests.append((ctrl_id, mod_path, test_path))

    assert not missing_paths, f"cosai-mapping.md cites paths that do not exist: {missing_paths}"
    assert not unrelated_tests, f"cosai-mapping.md cites tests that do not reference module: {unrelated_tests}"
