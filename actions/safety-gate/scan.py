#!/usr/bin/env python3
"""Datacore Safety Gate Scanner.

Scans PR diffs for secrets, personal data, and forbidden file patterns.
Only checks ADDED lines (lines starting with '+'), never removed lines.

Exit codes:
  0 - Clean, no issues found
  1 - Issues found (secrets, personal data, or forbidden files)
"""

import re
import subprocess
import sys


# ---------------------------------------------------------------------------
# Forbidden file patterns — these should never appear in a PR
# ---------------------------------------------------------------------------
FORBIDDEN_FILE_PATTERNS = [
    (r"org/.*\.org$", "org-mode file (internal GTD data)"),
    (r"journal/.*\.md$", "journal entry (private)"),
    (r"\.local\.md$", "local context file (private layer)"),
    (r"(^|/)\.env$", ".env file (secrets)"),
    (r"(^|/)\.env\.", ".env variant file (secrets)"),
    (r"(^|/)credentials/", "credentials directory"),
    (r"(^|/)secrets/", "secrets directory"),
]

# ---------------------------------------------------------------------------
# Secret patterns — detect leaked credentials in added lines
# ---------------------------------------------------------------------------
SECRET_PATTERNS = [
    # Specific token formats first (before generic "token = ..." pattern)
    (r"sk-[a-zA-Z0-9]{20,}", "OpenAI/Anthropic API key"),
    (r"ghp_[a-zA-Z0-9]{36}", "GitHub Personal Access Token"),
    (r"gho_[a-zA-Z0-9]{36}", "GitHub OAuth token"),
    (
        r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----",
        "Private key",
    ),
    (r"bearer\s+[a-zA-Z0-9_\-\.]{20,}", "Bearer token"),
    # Generic patterns last
    (
        r"(api[_\-]?key|apikey)\s*[=:]\s*[\"']?[a-zA-Z0-9_\-]{20,}",
        "Possible API key",
    ),
    (
        r"(secret|token|password|passwd|pwd)\s*[=:]\s*[\"']?[a-zA-Z0-9_\-]{8,}",
        "Possible secret/token/password",
    ),
]

# ---------------------------------------------------------------------------
# Personal data patterns — detect leaked PII in added lines
# ---------------------------------------------------------------------------
PERSONAL_DATA_PATTERNS = [
    (r"/Users/[a-zA-Z0-9_\-]+/", "macOS absolute path"),
    (r"/home/[a-zA-Z0-9_\-]+/", "Linux absolute path"),
    (r"C:\\\\Users\\\\[a-zA-Z0-9_\-]+\\\\", "Windows absolute path"),
    (
        r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
        "Email address",
    ),
]

# ---------------------------------------------------------------------------
# Allowlist — patterns that look like secrets/PII but are safe
# ---------------------------------------------------------------------------
ALLOWLIST_PATTERNS = [
    r"example\.com",
    r"your[\-_].*@",
    r"YOUR[\-_]",
    r"placeholder",
    r"EXAMPLE",
    r"xxx+",
    r"changeme",
    r"<[^>]*>",           # template placeholders like <your-key>
    r"PLACEHOLDER",
    r"your[_\-]?api[_\-]?key",
    r"your[_\-]?secret",
    r"your[_\-]?token",
    r"your[_\-]?password",
    r"noreply@",                       # automated no-reply addresses
    r"actions@github\.com",            # GitHub Actions bot
    r"Co-Authored-By:",                # git commit trailers
    r"@[a-zA-Z0-9\-]+/[a-zA-Z0-9\-]+",  # npm scoped packages (@scope/pkg)
    r"dependabot",                     # dependabot addresses
]


def is_allowlisted(line: str) -> bool:
    """Check if a line matches any allowlist pattern (case-insensitive)."""
    for pattern in ALLOWLIST_PATTERNS:
        if re.search(pattern, line, re.IGNORECASE):
            return True
    return False


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


def get_diff() -> str:
    """Get the full unified diff against origin/main."""
    return run_git("diff", "origin/main...HEAD")


def parse_diff_added_lines(diff_text: str) -> list[tuple[str, int, str]]:
    """Parse unified diff and extract only added lines.

    Returns list of (filename, line_number, line_content) tuples.
    Only lines starting with '+' (but not '+++') are included.
    """
    results = []
    current_file = None
    current_line = 0

    for raw_line in diff_text.splitlines():
        # Track which file we're in
        if raw_line.startswith("+++ b/"):
            current_file = raw_line[6:]
            continue
        if raw_line.startswith("--- "):
            continue

        # Track line numbers from hunk headers
        hunk_match = re.match(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@", raw_line)
        if hunk_match:
            current_line = int(hunk_match.group(1))
            continue

        # Only process added lines (starting with '+')
        if raw_line.startswith("+") and not raw_line.startswith("+++"):
            if current_file:
                results.append((current_file, current_line, raw_line[1:]))
            current_line += 1
        elif raw_line.startswith("-"):
            # Deleted lines don't advance the target line counter
            pass
        else:
            # Context lines advance the counter
            current_line += 1

    return results


def scan_forbidden_files(changed_files: list[str]) -> list[str]:
    """Check changed files against forbidden patterns.

    Returns list of GitHub Actions error annotation strings.
    """
    errors = []
    for filepath in changed_files:
        for pattern, description in FORBIDDEN_FILE_PATTERNS:
            if re.search(pattern, filepath):
                errors.append(
                    f"::error file={filepath},line=1"
                    f"::Forbidden file: {description} — {filepath}"
                )
                break  # one error per file is enough
    return errors


def scan_content_patterns(
    added_lines: list[tuple[str, int, str]],
    patterns: list[tuple[str, str]],
    category: str,
) -> list[str]:
    """Scan added lines against a set of regex patterns.

    Returns list of GitHub Actions error annotation strings.
    Skips lines that match the allowlist.
    """
    errors = []
    for filepath, line_num, content in added_lines:
        if is_allowlisted(content):
            continue
        for pattern, description in patterns:
            if re.search(pattern, content, re.IGNORECASE):
                errors.append(
                    f"::error file={filepath},line={line_num}"
                    f"::{category}: {description}"
                )
                break  # one error per line is enough
    return errors


def main() -> int:
    """Run the safety gate scan. Returns 0 if clean, 1 if issues found."""
    errors: list[str] = []

    # 1. Get changed files and check for forbidden patterns
    changed_files = get_changed_files()
    errors.extend(scan_forbidden_files(changed_files))

    # 2. Get diff and parse added lines
    diff_text = get_diff()
    added_lines = parse_diff_added_lines(diff_text)

    # 3. Scan for secrets
    errors.extend(scan_content_patterns(added_lines, SECRET_PATTERNS, "Secret detected"))

    # 4. Scan for personal data
    errors.extend(
        scan_content_patterns(added_lines, PERSONAL_DATA_PATTERNS, "Personal data")
    )

    # 5. Report results
    if errors:
        print(f"\n{'='*60}")
        print(f"Safety Gate: {len(errors)} issue(s) found")
        print(f"{'='*60}\n")
        for error in errors:
            print(error)
        print(f"\n{'='*60}")
        print("Fix the issues above before merging.")
        print(f"{'='*60}\n")
        return 1

    print("Safety Gate: PASSED (no issues found)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
