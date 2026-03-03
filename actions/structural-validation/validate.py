#!/usr/bin/env python3
"""Datacore Structural Validation.

Classifies PRs by type based on changed file patterns and runs
type-specific validations:
  - module:     module.yaml required fields, semver version
  - dip:        required sections and header fields, valid status
  - agent:      Agent Context section (DIP-0016)
  - python:     ruff linting (graceful skip if unavailable)

Exit codes:
  0 - All validations passed
  1 - One or more validations failed
"""

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# PR type classification rules
# ---------------------------------------------------------------------------
TYPE_RULES: list[tuple[str, str]] = [
    # pattern, type_label
    (r"(^|/)module\.yaml$", "module"),
    (r"\.datacore/modules/.*(?<!\.md)$", "module"),
    (r"(^|/)agents/.*\.md$", "agent"),
    (r"(^|/)commands/.*\.md$", "command"),
    (r"(^|/)dips/DIP-\d{4}", "dip"),
    (r"\.py$", "python"),
    (r"\.(ts|tsx)$", "typescript"),
    (r"\.md$", "docs"),
]

# ---------------------------------------------------------------------------
# DIP validation constants
# ---------------------------------------------------------------------------
DIP_REQUIRED_SECTIONS = [
    "## Summary",
    "## Motivation",
    "## Specification",
]

DIP_REQUIRED_HEADER_FIELDS = [
    "**DIP**",
    "**Title**",
    "**Status**",
    "**Type**",
]

DIP_VALID_STATUSES = {
    "Draft",
    "Proposed",
    "Accepted",
    "Implemented",
    "Rejected",
}

# ---------------------------------------------------------------------------
# Semver regex (major.minor.patch, optional pre-release)
# ---------------------------------------------------------------------------
SEMVER_RE = re.compile(
    r"^\d+\.\d+\.\d+(-[a-zA-Z0-9]+(\.[a-zA-Z0-9]+)*)?$"
)


def run_git(*args: str) -> str:
    """Run a git command and return stdout."""
    result = subprocess.run(
        ["git", *args],
        capture_output=True,
        text=True,
    )
    return result.stdout


def get_changed_files() -> list[str]:
    """Get list of changed files (added, copied, modified, renamed)."""
    output = run_git("diff", "--name-only", "--diff-filter=ACMR", "origin/main...HEAD")
    return [f.strip() for f in output.strip().splitlines() if f.strip()]


def classify_pr(changed_files: list[str]) -> set[str]:
    """Classify PR by type based on changed file patterns.

    Returns a set of detected type labels.
    """
    types: set[str] = set()
    for filepath in changed_files:
        for pattern, type_label in TYPE_RULES:
            if re.search(pattern, filepath):
                types.add(type_label)
                break  # first match wins per file
    return types


def find_module_dirs(changed_files: list[str]) -> set[str]:
    """Find module directories from changed files.

    Looks for directories containing module.yaml among the changed files,
    or directories under .datacore/modules/ that were changed.
    """
    module_dirs: set[str] = set()

    for filepath in changed_files:
        # Direct module.yaml change
        if filepath.endswith("module.yaml"):
            module_dirs.add(str(Path(filepath).parent))
            continue

        # Files under .datacore/modules/
        match = re.match(r"(\.datacore/modules/[^/]+)", filepath)
        if match:
            module_dirs.add(match.group(1))

    return module_dirs


def validate_modules(changed_files: list[str]) -> list[str]:
    """Validate module PRs: check module.yaml exists and has required fields."""
    errors: list[str] = []
    module_dirs = find_module_dirs(changed_files)

    for module_dir in sorted(module_dirs):
        yaml_path = Path(module_dir) / "module.yaml"

        if not yaml_path.exists():
            errors.append(
                f"::error file={module_dir}/::Missing module.yaml in {module_dir}"
            )
            continue

        # Parse YAML
        try:
            import yaml
            with open(yaml_path) as f:
                data = yaml.safe_load(f)
        except ImportError:
            # Fallback: basic text parsing if pyyaml not available
            data = _parse_yaml_simple(yaml_path)
        except Exception as e:
            errors.append(
                f"::error file={yaml_path}::Invalid YAML: {e}"
            )
            continue

        if not isinstance(data, dict):
            errors.append(
                f"::error file={yaml_path}::module.yaml must be a YAML mapping"
            )
            continue

        # Check required fields
        for field in ("name", "version", "description"):
            if field not in data or not data[field]:
                errors.append(
                    f"::error file={yaml_path}::Missing required field: {field}"
                )

        # Validate semver
        version = str(data.get("version", ""))
        if version and not SEMVER_RE.match(version):
            errors.append(
                f"::error file={yaml_path}::Version '{version}' is not valid semver"
            )

    return errors


def _parse_yaml_simple(path: Path) -> dict:
    """Minimal YAML parser for key: value pairs (fallback if pyyaml missing)."""
    data = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if ":" in line and not line.startswith("#"):
                key, _, value = line.partition(":")
                key = key.strip()
                value = value.strip().strip("'\"")
                if value:
                    data[key] = value
    return data


def validate_dips(changed_files: list[str]) -> list[str]:
    """Validate DIP PRs: check required sections and header fields."""
    errors: list[str] = []

    dip_files = [
        f for f in changed_files
        if re.search(r"(^|/)dips/DIP-\d{4}.*\.md$", f)
    ]

    for filepath in dip_files:
        if not Path(filepath).exists():
            continue

        content = Path(filepath).read_text(encoding="utf-8", errors="replace")

        # Check required sections
        for section in DIP_REQUIRED_SECTIONS:
            if section not in content:
                errors.append(
                    f"::error file={filepath}::Missing required section: {section}"
                )

        # Check required header fields
        for field in DIP_REQUIRED_HEADER_FIELDS:
            if field not in content:
                errors.append(
                    f"::error file={filepath}::Missing required header field: {field}"
                )

        # Validate status value
        status_match = re.search(
            r"\*\*Status\*\*[:\s]*\*?\s*(\w+)", content
        )
        if status_match:
            status = status_match.group(1)
            if status not in DIP_VALID_STATUSES:
                errors.append(
                    f"::error file={filepath}::Invalid DIP status '{status}'. "
                    f"Must be one of: {', '.join(sorted(DIP_VALID_STATUSES))}"
                )

    return errors


def validate_agents(changed_files: list[str]) -> list[str]:
    """Validate agent PRs: check for Agent Context section (DIP-0016)."""
    errors: list[str] = []

    agent_files = [
        f for f in changed_files
        if re.search(r"(^|/)agents/.*\.md$", f)
    ]

    for filepath in agent_files:
        if not Path(filepath).exists():
            continue

        content = Path(filepath).read_text(encoding="utf-8", errors="replace")

        if "## Agent Context" not in content:
            errors.append(
                f"::error file={filepath}::Missing '## Agent Context' section "
                f"(required by DIP-0016)"
            )

    return errors


def validate_python(changed_files: list[str]) -> list[str]:
    """Run ruff on changed Python files (skip gracefully if unavailable)."""
    errors: list[str] = []

    py_files = [f for f in changed_files if f.endswith(".py") and Path(f).exists()]
    if not py_files:
        return errors

    ruff_path = shutil.which("ruff")
    if not ruff_path:
        print("::notice::ruff not available, skipping Python linting")
        return errors

    result = subprocess.run(
        [ruff_path, "check", "--output-format=github", *py_files],
        capture_output=True,
        text=True,
    )

    if result.returncode != 0 and result.stdout.strip():
        # ruff --output-format=github already produces ::error:: annotations
        for line in result.stdout.strip().splitlines():
            errors.append(line)

    return errors


def set_output(name: str, value: str) -> None:
    """Set a GitHub Actions output variable."""
    output_file = os.environ.get("GITHUB_OUTPUT")
    if output_file:
        with open(output_file, "a") as f:
            f.write(f"{name}={value}\n")
    else:
        # Fallback for local testing / older runners
        print(f"::set-output name={name}::{value}")


def main() -> int:
    """Run structural validation. Returns 0 if passed, 1 if failed."""
    errors: list[str] = []

    # 1. Get changed files
    changed_files = get_changed_files()
    if not changed_files:
        print("Structural Validation: No changed files detected")
        set_output("pr_types", "")
        return 0

    # 2. Classify PR
    pr_types = classify_pr(changed_files)
    types_str = ",".join(sorted(pr_types))
    set_output("pr_types", types_str)
    print(f"Detected PR types: {types_str or '(none)'}")

    # 3. Run type-specific validations
    if "module" in pr_types:
        print("\n--- Validating modules ---")
        errors.extend(validate_modules(changed_files))

    if "dip" in pr_types:
        print("\n--- Validating DIPs ---")
        errors.extend(validate_dips(changed_files))

    if "agent" in pr_types:
        print("\n--- Validating agents ---")
        errors.extend(validate_agents(changed_files))

    if "python" in pr_types:
        print("\n--- Linting Python ---")
        errors.extend(validate_python(changed_files))

    # 4. Report results
    if errors:
        print(f"\n{'='*60}")
        print(f"Structural Validation: {len(errors)} issue(s) found")
        print(f"{'='*60}\n")
        for error in errors:
            print(error)
        print(f"\n{'='*60}")
        print("Fix the issues above before merging.")
        print(f"{'='*60}\n")
        return 1

    print("\nStructural Validation: PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
