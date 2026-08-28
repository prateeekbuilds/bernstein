"""Guard: every ``copy .env.example`` instruction points at a tracked file.

``docker-compose.yaml`` (and potentially other config / docs files) tell the
reader to ``cp .env.example .env``.  If ``.gitignore`` swallows the template
(as ``.env.*`` did before the negation was added) a first-time reader stops
at step 1 with no way to tell whether the file is missing or they are.

This test scans tracked files for that instruction, resolves the referenced
``.env.example`` relative to the file that mentions it, and asserts it is
both present on disk **and** tracked by git.  ``git ls-files`` is the right
oracle — checking only the filesystem would pass on the machine where the
file exists but is ignored, which is exactly the state that produced #4723.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

# Pattern that matches instructions telling the reader to copy .env.example.
# Deliberately broad: we want to catch any phrasing that points a human at
# the file, not just the exact wording used today.
_COPY_ENV_EXAMPLE = re.compile(
    r"""
    (?:copy|cp)\s+    # the verb (English or shell)
    \.env\.example    # the source template
    """,
    re.IGNORECASE | re.VERBOSE,
)

# Files to scan.  We check every tracked file whose extension is likely to
# contain setup instructions.  Adjust if new file types start carrying them.
_SCANNABLE_EXTENSIONS = {".yaml", ".yml", ".md", ".txt", ".rst"}


def _git_tracked_files() -> set[str]:
    """Return the set of repo-relative paths that git currently tracks."""
    result = subprocess.run(
        ["git", "ls-files"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return set(result.stdout.splitlines())


def _find_copy_references() -> list[tuple[Path, int, Path]]:
    """Scan tracked files for ``copy .env.example`` instructions.

    Returns a list of ``(source_file, line_number, resolved_env_example)``
    tuples.  The resolved path is the ``.env.example`` that the instruction
    implicitly points at (same directory as the source file).
    """
    tracked = _git_tracked_files()
    references: list[tuple[Path, int, Path]] = []

    for rel_path in sorted(tracked):
        path = REPO_ROOT / rel_path
        if path.suffix not in _SCANNABLE_EXTENSIONS:
            continue
        # Skip example / fixture files that quote the instruction without
        # meaning it literally (e.g. a lint rule example or a plan template).
        # The issue's scope correction identifies these explicitly.
        rel_parts = Path(rel_path).parts
        if any(part in ("examples", "fixtures", "templates") for part in rel_parts):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            if _COPY_ENV_EXAMPLE.search(line):
                references.append((path, lineno, _candidate_templates(path)))

    return references


def _candidate_templates(source: Path) -> tuple[Path, ...]:
    """Where a reader of *source* could find the template it names.

    Two places, in the order a reader would look: beside the file that gives
    the instruction, then the repository root.

    Resolving to the sibling alone asks the wrong question. Whether a line is
    a real instruction or prose describing one cannot be told apart by its
    wording - the first attempt here matched on a dictionary of tokens
    ("linter", "allow-list") and its first miss was this change's own release
    note, which quotes `cp .env.example .env` while describing the fix and
    was read as demanding a template inside `docs/release-notes/fragments/`.

    Asking whether the reader can reach a tracked template needs no such
    guess: prose is satisfied by the root template, and the regression this
    guard exists for - the root template silently untracked - still fails,
    because then neither candidate resolves.
    """
    return (source.parent / ".env.example", REPO_ROOT / ".env.example")


def test_every_env_example_reference_is_tracked() -> None:
    """For each ``copy .env.example`` instruction, the target must be tracked."""
    tracked = _git_tracked_files()
    references = _find_copy_references()

    assert references, (
        "sanity check failed: expected at least docker-compose.yaml to reference "
        ".env.example, but no references were found — has the scan pattern drifted?"
    )

    missing: list[str] = []
    for source, lineno, candidates in references:
        # Tracked, not merely present: on the machine where the template
        # exists but .gitignore swallows it, a filesystem check passes and
        # every clone of the repository still has nothing to copy.
        if any(str(c.relative_to(REPO_ROOT)) in tracked for c in candidates):
            continue
        where = " or ".join(str(c.relative_to(REPO_ROOT)) for c in candidates)
        present = [c for c in candidates if c.is_file()]
        why = "exists but is NOT tracked - check .gitignore" if present else "no such file"
        missing.append(f"  {source.relative_to(REPO_ROOT)}:{lineno} -> {where} ({why})")

    assert not missing, (
        "The following files instruct readers to copy .env.example, but the "
        "referenced template is missing or not tracked by git:\n"
        + "\n".join(missing)
        + "\n\nFix: create the .env.example and ensure .gitignore does not swallow it. "
        "See issue #4723."
    )
