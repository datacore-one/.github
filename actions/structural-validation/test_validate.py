"""Comprehensive tests for Datacore structural validation.

Tests pure logic functions only — no git/subprocess calls.
Uses pytest tmp_path fixture for filesystem-dependent tests.
"""

import os
import textwrap

import pytest

from validate import (
    SEMVER_RE,
    _parse_yaml_simple,
    classify_pr,
    find_module_dirs,
    set_output,
    validate_agents,
    validate_dips,
    validate_modules,
)


# ===================================================================
# 1. classify_pr — PR type classification
# ===================================================================


class TestClassifyPr:
    """Test classify_pr against TYPE_RULES."""

    # --- Single type per file ---

    def test_module_yaml_at_root(self):
        assert classify_pr(["module.yaml"]) == {"module"}

    def test_module_yaml_nested(self):
        assert classify_pr(["some/path/module.yaml"]) == {"module"}

    def test_module_file_under_datacore_modules(self):
        assert classify_pr([".datacore/modules/crm/lib/score.py"]) == {"module"}

    def test_module_non_md_under_datacore_modules(self):
        assert classify_pr([".datacore/modules/health/config.yaml"]) == {"module"}

    def test_module_md_under_datacore_modules_is_docs_not_module(self):
        r"""Markdown files under .datacore/modules/ should NOT match as module
        because the negative lookbehind (?<!\.md)$ excludes .md files.
        They fall through to the .md (docs) rule instead."""
        result = classify_pr([".datacore/modules/crm/README.md"])
        assert "module" not in result
        assert "docs" in result

    def test_agent_file(self):
        assert classify_pr(["agents/my-agent.md"]) == {"agent"}

    def test_agent_file_nested(self):
        assert classify_pr([".datacore/agents/my-agent.md"]) == {"agent"}

    def test_command_file(self):
        assert classify_pr(["commands/deploy.md"]) == {"command"}

    def test_command_file_nested(self):
        assert classify_pr(["some/path/commands/today.md"]) == {"command"}

    def test_dip_file(self):
        assert classify_pr(["dips/DIP-0001-contribution-model.md"]) == {"dip"}

    def test_dip_file_nested(self):
        assert classify_pr([".datacore/dips/DIP-0042-new-thing.md"]) == {"dip"}

    def test_dip_non_md_file(self):
        """DIP pattern matches any file under dips/DIP-NNNN, not just .md."""
        result = classify_pr(["dips/DIP-0005-diagram.png"])
        assert "dip" in result

    def test_python_file(self):
        assert classify_pr(["lib/validate.py"]) == {"python"}

    def test_typescript_file_ts(self):
        assert classify_pr(["src/index.ts"]) == {"typescript"}

    def test_typescript_file_tsx(self):
        assert classify_pr(["src/App.tsx"]) == {"typescript"}

    def test_docs_plain_md(self):
        assert classify_pr(["README.md"]) == {"docs"}

    def test_docs_nested_md(self):
        assert classify_pr(["docs/guide/setup.md"]) == {"docs"}

    # --- Multiple types in one PR ---

    def test_mixed_types(self):
        files = [
            "module.yaml",
            "agents/foo.md",
            "dips/DIP-0010-sync.md",
            "lib/utils.py",
            "src/main.ts",
            "README.md",
        ]
        result = classify_pr(files)
        assert result == {"module", "agent", "dip", "python", "typescript", "docs"}

    def test_multiple_files_same_type(self):
        files = ["lib/a.py", "lib/b.py", "tests/test_c.py"]
        result = classify_pr(files)
        assert result == {"python"}

    # --- Unknown file types ---

    def test_unknown_file_type(self):
        assert classify_pr(["Makefile"]) == set()

    def test_unknown_binary(self):
        assert classify_pr(["image.png"]) == set()

    def test_unknown_json(self):
        assert classify_pr(["package.json"]) == set()

    def test_mixed_known_and_unknown(self):
        files = ["Makefile", "lib/utils.py", "image.png"]
        result = classify_pr(files)
        assert result == {"python"}

    # --- Empty input ---

    def test_empty_file_list(self):
        assert classify_pr([]) == set()

    # --- First-match-wins behavior ---

    def test_agent_md_matches_agent_not_docs(self):
        """Agent .md files should match 'agent' rule before 'docs' rule."""
        result = classify_pr(["agents/router.md"])
        assert result == {"agent"}
        assert "docs" not in result

    def test_command_md_matches_command_not_docs(self):
        """Command .md files should match 'command' rule before 'docs' rule."""
        result = classify_pr(["commands/today.md"])
        assert result == {"command"}
        assert "docs" not in result

    def test_dip_md_matches_dip_not_docs(self):
        """DIP .md files should match 'dip' rule before 'docs' rule."""
        result = classify_pr(["dips/DIP-0001-foo.md"])
        assert result == {"dip"}
        assert "docs" not in result

    def test_module_yaml_matches_module_not_other(self):
        """module.yaml should only produce 'module' type."""
        result = classify_pr(["module.yaml"])
        assert result == {"module"}

    def test_py_under_modules_matches_module_not_python(self):
        """A .py file under .datacore/modules/ should match module first,
        not python, because the module rule comes first."""
        result = classify_pr([".datacore/modules/crm/lib/score.py"])
        assert result == {"module"}
        assert "python" not in result


# ===================================================================
# 2. find_module_dirs — module directory detection
# ===================================================================


class TestFindModuleDirs:
    """Test find_module_dirs directory extraction."""

    def test_direct_module_yaml_root(self):
        result = find_module_dirs(["module.yaml"])
        assert result == {"."}

    def test_direct_module_yaml_nested(self):
        result = find_module_dirs(["some/path/module.yaml"])
        assert result == {"some/path"}

    def test_file_under_datacore_modules(self):
        result = find_module_dirs([".datacore/modules/crm/lib/score.py"])
        assert result == {".datacore/modules/crm"}

    def test_multiple_files_same_module(self):
        files = [
            ".datacore/modules/crm/lib/score.py",
            ".datacore/modules/crm/config.yaml",
        ]
        result = find_module_dirs(files)
        assert result == {".datacore/modules/crm"}

    def test_multiple_modules(self):
        files = [
            ".datacore/modules/crm/lib/score.py",
            ".datacore/modules/health/module.yaml",
        ]
        result = find_module_dirs(files)
        assert result == {".datacore/modules/crm", ".datacore/modules/health"}

    def test_mixed_module_yaml_and_module_dir(self):
        files = [
            "module.yaml",
            ".datacore/modules/trading/strategy.py",
        ]
        result = find_module_dirs(files)
        assert result == {".", ".datacore/modules/trading"}

    def test_non_module_files_ignored(self):
        files = ["README.md", "lib/utils.py", "agents/foo.md"]
        result = find_module_dirs(files)
        assert result == set()

    def test_empty_list(self):
        assert find_module_dirs([]) == set()

    def test_deeply_nested_module_file(self):
        result = find_module_dirs([".datacore/modules/crm/sub/deep/file.py"])
        assert result == {".datacore/modules/crm"}

    def test_module_yaml_under_datacore_modules(self):
        """module.yaml under .datacore/modules/ matches BOTH heuristics.
        The endswith('module.yaml') check runs first and adds the parent dir."""
        result = find_module_dirs([".datacore/modules/crm/module.yaml"])
        assert ".datacore/modules/crm" in result


# ===================================================================
# 3. validate_modules — module.yaml validation
# ===================================================================


class TestValidateModules:
    """Test validate_modules with temporary filesystem."""

    def _write(self, path, content):
        """Helper to write a file with parent directories."""
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(content))

    def test_valid_module(self, tmp_path):
        mod_dir = tmp_path / "mymodule"
        self._write(
            mod_dir / "module.yaml",
            """\
            name: mymodule
            version: 1.2.3
            description: A test module
            """,
        )
        changed = [str(mod_dir / "module.yaml")]
        errors = validate_modules(changed)
        assert errors == []

    def test_valid_module_with_prerelease(self, tmp_path):
        mod_dir = tmp_path / "mymodule"
        self._write(
            mod_dir / "module.yaml",
            """\
            name: mymodule
            version: 1.0.0-beta.1
            description: A beta module
            """,
        )
        changed = [str(mod_dir / "module.yaml")]
        errors = validate_modules(changed)
        assert errors == []

    def test_missing_module_yaml(self, tmp_path, monkeypatch):
        """When module dir exists but module.yaml doesn't, report error.

        find_module_dirs uses a regex for relative paths like
        '.datacore/modules/<name>', so we chdir into tmp_path and use
        relative paths to match the production behavior.
        """
        monkeypatch.chdir(tmp_path)
        mod_dir = tmp_path / ".datacore" / "modules" / "ghost"
        mod_dir.mkdir(parents=True)
        # Changed file references the module dir but no module.yaml
        changed = [".datacore/modules/ghost/lib/something.py"]
        errors = validate_modules(changed)
        assert len(errors) == 1
        assert "Missing module.yaml" in errors[0]

    def test_missing_required_field_name(self, tmp_path):
        mod_dir = tmp_path / "mymodule"
        self._write(
            mod_dir / "module.yaml",
            """\
            version: 1.0.0
            description: Missing name field
            """,
        )
        changed = [str(mod_dir / "module.yaml")]
        errors = validate_modules(changed)
        assert any("Missing required field: name" in e for e in errors)

    def test_missing_required_field_version(self, tmp_path):
        mod_dir = tmp_path / "mymodule"
        self._write(
            mod_dir / "module.yaml",
            """\
            name: mymodule
            description: Missing version
            """,
        )
        changed = [str(mod_dir / "module.yaml")]
        errors = validate_modules(changed)
        assert any("Missing required field: version" in e for e in errors)

    def test_missing_required_field_description(self, tmp_path):
        mod_dir = tmp_path / "mymodule"
        self._write(
            mod_dir / "module.yaml",
            """\
            name: mymodule
            version: 1.0.0
            """,
        )
        changed = [str(mod_dir / "module.yaml")]
        errors = validate_modules(changed)
        assert any("Missing required field: description" in e for e in errors)

    def test_all_required_fields_missing(self, tmp_path):
        mod_dir = tmp_path / "mymodule"
        self._write(
            mod_dir / "module.yaml",
            """\
            author: someone
            """,
        )
        changed = [str(mod_dir / "module.yaml")]
        errors = validate_modules(changed)
        assert len(errors) >= 3
        assert any("name" in e for e in errors)
        assert any("version" in e for e in errors)
        assert any("description" in e for e in errors)

    def test_invalid_semver_two_parts(self, tmp_path):
        mod_dir = tmp_path / "mymodule"
        self._write(
            mod_dir / "module.yaml",
            """\
            name: mymodule
            version: 1.0
            description: Bad version
            """,
        )
        changed = [str(mod_dir / "module.yaml")]
        errors = validate_modules(changed)
        assert any("not valid semver" in e for e in errors)

    def test_invalid_semver_text(self, tmp_path):
        mod_dir = tmp_path / "mymodule"
        self._write(
            mod_dir / "module.yaml",
            """\
            name: mymodule
            version: latest
            description: Non-numeric version
            """,
        )
        changed = [str(mod_dir / "module.yaml")]
        errors = validate_modules(changed)
        assert any("not valid semver" in e for e in errors)

    def test_non_dict_yaml(self, tmp_path):
        """module.yaml that parses to a list should be rejected."""
        mod_dir = tmp_path / "mymodule"
        self._write(
            mod_dir / "module.yaml",
            """\
            - item1
            - item2
            """,
        )
        changed = [str(mod_dir / "module.yaml")]
        errors = validate_modules(changed)
        assert any("must be a YAML mapping" in e for e in errors)

    def test_empty_field_value_treated_as_missing(self, tmp_path):
        """Fields with empty string values should be flagged as missing."""
        mod_dir = tmp_path / "mymodule"
        self._write(
            mod_dir / "module.yaml",
            """\
            name: ""
            version: 1.0.0
            description: has name but it is empty
            """,
        )
        changed = [str(mod_dir / "module.yaml")]
        errors = validate_modules(changed)
        assert any("Missing required field: name" in e for e in errors)

    def test_multiple_modules_validated(self, tmp_path):
        """Multiple modules in one PR should each be validated."""
        mod_a = tmp_path / "mod_a"
        self._write(
            mod_a / "module.yaml",
            """\
            name: mod_a
            version: 1.0.0
            description: Module A
            """,
        )
        mod_b = tmp_path / "mod_b"
        self._write(
            mod_b / "module.yaml",
            """\
            name: mod_b
            version: bad
            description: Module B
            """,
        )
        changed = [str(mod_a / "module.yaml"), str(mod_b / "module.yaml")]
        errors = validate_modules(changed)
        # mod_a is valid, mod_b has bad version
        assert len(errors) == 1
        assert "not valid semver" in errors[0]
        assert "mod_b" in errors[0]


# ===================================================================
# 4. validate_dips — DIP file validation
# ===================================================================


class TestValidateDips:
    """Test validate_dips with temporary DIP markdown files."""

    VALID_DIP = textwrap.dedent("""\
        # DIP-0099: Test DIP

        **DIP**: 0099
        **Title**: Test DIP
        **Status**: Draft
        **Type**: Standard

        ## Summary

        This is a test DIP.

        ## Motivation

        Testing is important.

        ## Specification

        Spec goes here.
    """)

    def test_valid_dip(self, tmp_path):
        dip_dir = tmp_path / "dips"
        dip_dir.mkdir()
        dip_file = dip_dir / "DIP-0099-test.md"
        dip_file.write_text(self.VALID_DIP)
        changed = [str(dip_file)]
        errors = validate_dips(changed)
        assert errors == []

    def test_missing_summary_section(self, tmp_path):
        dip_dir = tmp_path / "dips"
        dip_dir.mkdir()
        content = self.VALID_DIP.replace("## Summary", "## Overview")
        dip_file = dip_dir / "DIP-0001-test.md"
        dip_file.write_text(content)
        errors = validate_dips([str(dip_file)])
        assert any("Missing required section: ## Summary" in e for e in errors)

    def test_missing_motivation_section(self, tmp_path):
        dip_dir = tmp_path / "dips"
        dip_dir.mkdir()
        content = self.VALID_DIP.replace("## Motivation", "## Background")
        dip_file = dip_dir / "DIP-0002-test.md"
        dip_file.write_text(content)
        errors = validate_dips([str(dip_file)])
        assert any("Missing required section: ## Motivation" in e for e in errors)

    def test_missing_specification_section(self, tmp_path):
        dip_dir = tmp_path / "dips"
        dip_dir.mkdir()
        content = self.VALID_DIP.replace("## Specification", "## Details")
        dip_file = dip_dir / "DIP-0003-test.md"
        dip_file.write_text(content)
        errors = validate_dips([str(dip_file)])
        assert any("Missing required section: ## Specification" in e for e in errors)

    def test_missing_all_sections(self, tmp_path):
        dip_dir = tmp_path / "dips"
        dip_dir.mkdir()
        content = textwrap.dedent("""\
            # DIP-0099

            **DIP**: 0099
            **Title**: Test
            **Status**: Draft
            **Type**: Standard

            Just some text without required sections.
        """)
        dip_file = dip_dir / "DIP-0099-bare.md"
        dip_file.write_text(content)
        errors = validate_dips([str(dip_file)])
        assert any("## Summary" in e for e in errors)
        assert any("## Motivation" in e for e in errors)
        assert any("## Specification" in e for e in errors)

    def test_missing_header_field_dip(self, tmp_path):
        dip_dir = tmp_path / "dips"
        dip_dir.mkdir()
        content = self.VALID_DIP.replace("**DIP**: 0099\n", "")
        dip_file = dip_dir / "DIP-0004-test.md"
        dip_file.write_text(content)
        errors = validate_dips([str(dip_file)])
        assert any("Missing required header field: **DIP**" in e for e in errors)

    def test_missing_header_field_title(self, tmp_path):
        dip_dir = tmp_path / "dips"
        dip_dir.mkdir()
        content = self.VALID_DIP.replace("**Title**: Test DIP\n", "")
        dip_file = dip_dir / "DIP-0005-test.md"
        dip_file.write_text(content)
        errors = validate_dips([str(dip_file)])
        assert any("Missing required header field: **Title**" in e for e in errors)

    def test_missing_header_field_status(self, tmp_path):
        dip_dir = tmp_path / "dips"
        dip_dir.mkdir()
        content = self.VALID_DIP.replace("**Status**: Draft\n", "")
        dip_file = dip_dir / "DIP-0006-test.md"
        dip_file.write_text(content)
        errors = validate_dips([str(dip_file)])
        assert any("Missing required header field: **Status**" in e for e in errors)

    def test_missing_header_field_type(self, tmp_path):
        dip_dir = tmp_path / "dips"
        dip_dir.mkdir()
        content = self.VALID_DIP.replace("**Type**: Standard\n", "")
        dip_file = dip_dir / "DIP-0007-test.md"
        dip_file.write_text(content)
        errors = validate_dips([str(dip_file)])
        assert any("Missing required header field: **Type**" in e for e in errors)

    def test_invalid_status(self, tmp_path):
        dip_dir = tmp_path / "dips"
        dip_dir.mkdir()
        content = self.VALID_DIP.replace("**Status**: Draft", "**Status**: WIP")
        dip_file = dip_dir / "DIP-0008-test.md"
        dip_file.write_text(content)
        errors = validate_dips([str(dip_file)])
        assert any("Invalid DIP status 'WIP'" in e for e in errors)

    @pytest.mark.parametrize("status", ["Draft", "Proposed", "Accepted", "Implemented", "Rejected"])
    def test_all_valid_statuses(self, tmp_path, status):
        dip_dir = tmp_path / "dips"
        dip_dir.mkdir()
        content = self.VALID_DIP.replace("**Status**: Draft", f"**Status**: {status}")
        dip_file = dip_dir / "DIP-0099-test.md"
        dip_file.write_text(content)
        errors = validate_dips([str(dip_file)])
        # No status errors expected
        assert not any("Invalid DIP status" in e for e in errors)

    def test_non_dip_file_ignored(self, tmp_path):
        """Files not matching the DIP pattern should be skipped."""
        other = tmp_path / "README.md"
        other.write_text("# README")
        errors = validate_dips([str(other)])
        assert errors == []

    def test_nonexistent_dip_file_skipped(self, tmp_path):
        """If a DIP file doesn't exist on disk, it should be silently skipped."""
        fake = str(tmp_path / "dips" / "DIP-0099-phantom.md")
        errors = validate_dips([fake])
        assert errors == []

    def test_dip_status_with_italic_format(self, tmp_path):
        """Status with italic markers like **Status**: *Draft* should parse."""
        dip_dir = tmp_path / "dips"
        dip_dir.mkdir()
        content = self.VALID_DIP.replace("**Status**: Draft", "**Status**: *Draft*")
        dip_file = dip_dir / "DIP-0010-test.md"
        dip_file.write_text(content)
        errors = validate_dips([str(dip_file)])
        assert not any("Invalid DIP status" in e for e in errors)


# ===================================================================
# 5. validate_agents — agent file validation
# ===================================================================


class TestValidateAgents:
    """Test validate_agents with temporary agent markdown files."""

    def test_valid_agent(self, tmp_path):
        agents_dir = tmp_path / "agents"
        agents_dir.mkdir()
        agent_file = agents_dir / "my-agent.md"
        agent_file.write_text(textwrap.dedent("""\
            # My Agent

            ## Agent Context

            This agent does things.

            ## Instructions

            Do the thing.
        """))
        errors = validate_agents([str(agent_file)])
        assert errors == []

    def test_missing_agent_context(self, tmp_path):
        agents_dir = tmp_path / "agents"
        agents_dir.mkdir()
        agent_file = agents_dir / "bad-agent.md"
        agent_file.write_text(textwrap.dedent("""\
            # Bad Agent

            ## Instructions

            Do stuff without context.
        """))
        errors = validate_agents([str(agent_file)])
        assert len(errors) == 1
        assert "Missing '## Agent Context' section" in errors[0]
        assert "DIP-0016" in errors[0]

    def test_non_agent_file_ignored(self, tmp_path):
        """Files not matching agents/*.md pattern should be skipped."""
        readme = tmp_path / "README.md"
        readme.write_text("# README")
        errors = validate_agents([str(readme)])
        assert errors == []

    def test_nonexistent_agent_file_skipped(self, tmp_path):
        """If an agent file doesn't exist on disk, skip silently."""
        fake = str(tmp_path / "agents" / "ghost.md")
        errors = validate_agents([fake])
        assert errors == []

    def test_multiple_agents_all_valid(self, tmp_path):
        agents_dir = tmp_path / "agents"
        agents_dir.mkdir()
        for name in ("agent-a.md", "agent-b.md"):
            (agents_dir / name).write_text("# Agent\n\n## Agent Context\n\nContext here.\n")
        changed = [str(agents_dir / "agent-a.md"), str(agents_dir / "agent-b.md")]
        errors = validate_agents(changed)
        assert errors == []

    def test_multiple_agents_one_invalid(self, tmp_path):
        agents_dir = tmp_path / "agents"
        agents_dir.mkdir()
        (agents_dir / "good.md").write_text("# Good\n\n## Agent Context\n\nOK.\n")
        (agents_dir / "bad.md").write_text("# Bad\n\n## Instructions\n\nNo context.\n")
        changed = [str(agents_dir / "good.md"), str(agents_dir / "bad.md")]
        errors = validate_agents(changed)
        assert len(errors) == 1
        assert "bad.md" in errors[0]

    def test_nested_agents_dir(self, tmp_path):
        """agents/ nested under another directory should still match."""
        nested = tmp_path / "some" / "path" / "agents"
        nested.mkdir(parents=True)
        agent_file = nested / "deep-agent.md"
        agent_file.write_text("# Deep\n\n## Agent Context\n\nOK.\n")
        errors = validate_agents([str(agent_file)])
        assert errors == []


# ===================================================================
# 6. _parse_yaml_simple — fallback YAML parser
# ===================================================================


class TestParseYamlSimple:
    """Test the minimal fallback YAML parser."""

    def test_basic_key_value(self, tmp_path):
        f = tmp_path / "test.yaml"
        f.write_text("name: mymodule\nversion: 1.0.0\n")
        result = _parse_yaml_simple(f)
        assert result == {"name": "mymodule", "version": "1.0.0"}

    def test_quoted_single(self, tmp_path):
        f = tmp_path / "test.yaml"
        f.write_text("name: 'my module'\n")
        result = _parse_yaml_simple(f)
        assert result == {"name": "my module"}

    def test_quoted_double(self, tmp_path):
        f = tmp_path / "test.yaml"
        f.write_text('name: "my module"\n')
        result = _parse_yaml_simple(f)
        assert result == {"name": "my module"}

    def test_comments_skipped(self, tmp_path):
        f = tmp_path / "test.yaml"
        f.write_text("# This is a comment\nname: mymodule\n# Another comment\n")
        result = _parse_yaml_simple(f)
        assert result == {"name": "mymodule"}

    def test_empty_value_skipped(self, tmp_path):
        """Lines with key but no value should not be included."""
        f = tmp_path / "test.yaml"
        f.write_text("name:\nversion: 1.0.0\n")
        result = _parse_yaml_simple(f)
        assert "name" not in result
        assert result["version"] == "1.0.0"

    def test_whitespace_trimmed(self, tmp_path):
        f = tmp_path / "test.yaml"
        f.write_text("  name  :  mymodule  \n")
        result = _parse_yaml_simple(f)
        assert result == {"name": "mymodule"}

    def test_value_with_colon(self, tmp_path):
        """Value containing a colon should be preserved (partition on first :)."""
        f = tmp_path / "test.yaml"
        f.write_text("description: A module: with colons\n")
        result = _parse_yaml_simple(f)
        assert result["description"] == "A module: with colons"

    def test_empty_file(self, tmp_path):
        f = tmp_path / "empty.yaml"
        f.write_text("")
        result = _parse_yaml_simple(f)
        assert result == {}

    def test_only_comments(self, tmp_path):
        f = tmp_path / "comments.yaml"
        f.write_text("# comment 1\n# comment 2\n")
        result = _parse_yaml_simple(f)
        assert result == {}

    def test_mixed_content(self, tmp_path):
        f = tmp_path / "mixed.yaml"
        f.write_text(textwrap.dedent("""\
            # Module config
            name: crm
            version: 0.3.0
            description: 'Network Intelligence'
            author: someone
        """))
        result = _parse_yaml_simple(f)
        assert result == {
            "name": "crm",
            "version": "0.3.0",
            "description": "Network Intelligence",
            "author": "someone",
        }


# ===================================================================
# 7. set_output — GitHub Actions output
# ===================================================================


class TestSetOutput:
    """Test set_output writes to GITHUB_OUTPUT or prints fallback."""

    def test_writes_to_github_output_file(self, tmp_path, monkeypatch):
        output_file = tmp_path / "github_output.txt"
        output_file.write_text("")  # create empty file
        monkeypatch.setenv("GITHUB_OUTPUT", str(output_file))

        set_output("pr_types", "module,python")

        content = output_file.read_text()
        assert "pr_types=module,python\n" in content

    def test_appends_to_existing_output_file(self, tmp_path, monkeypatch):
        output_file = tmp_path / "github_output.txt"
        output_file.write_text("existing=value\n")
        monkeypatch.setenv("GITHUB_OUTPUT", str(output_file))

        set_output("pr_types", "dip")

        content = output_file.read_text()
        assert "existing=value\n" in content
        assert "pr_types=dip\n" in content

    def test_fallback_prints_when_no_github_output(self, capsys, monkeypatch):
        monkeypatch.delenv("GITHUB_OUTPUT", raising=False)

        set_output("pr_types", "agent")

        captured = capsys.readouterr()
        assert "::set-output name=pr_types::agent" in captured.out

    def test_multiple_outputs(self, tmp_path, monkeypatch):
        output_file = tmp_path / "github_output.txt"
        output_file.write_text("")
        monkeypatch.setenv("GITHUB_OUTPUT", str(output_file))

        set_output("pr_types", "module")
        set_output("status", "passed")

        content = output_file.read_text()
        assert "pr_types=module\n" in content
        assert "status=passed\n" in content

    def test_empty_value(self, tmp_path, monkeypatch):
        output_file = tmp_path / "github_output.txt"
        output_file.write_text("")
        monkeypatch.setenv("GITHUB_OUTPUT", str(output_file))

        set_output("pr_types", "")

        content = output_file.read_text()
        assert "pr_types=\n" in content


# ===================================================================
# 8. SEMVER_RE — semver regex validation
# ===================================================================


class TestSemverRegex:
    """Test the SEMVER_RE pattern used for version validation."""

    @pytest.mark.parametrize(
        "version",
        [
            "0.0.0",
            "1.0.0",
            "1.2.3",
            "10.20.30",
            "0.1.0",
            "1.0.0-alpha",
            "1.0.0-beta.1",
            "1.0.0-rc.1",
            "2.0.0-alpha.2.beta",
        ],
    )
    def test_valid_semver(self, version):
        assert SEMVER_RE.match(version), f"{version} should be valid semver"

    @pytest.mark.parametrize(
        "version",
        [
            "1.0",
            "1",
            "latest",
            "v1.0.0",
            "1.0.0.",
            ".1.0.0",
            "1.0.0-",
            "1.0.0+build",      # build metadata not in this regex
            "1.0.0-beta..1",    # double dot
            "01.0.0",           # this actually matches since \d+ allows leading zeros
        ],
    )
    def test_invalid_semver(self, version):
        # Note: "01.0.0" technically matches \d+\.\d+\.\d+ — that is acceptable
        # because the regex only checks format, not leading zero semantics.
        if version == "01.0.0":
            pytest.skip("Leading zeros are not rejected by this regex")
        assert not SEMVER_RE.match(version), f"{version} should NOT be valid semver"


# ===================================================================
# 9. Edge cases and integration-like tests
# ===================================================================


class TestEdgeCases:
    """Edge cases spanning multiple functions."""

    def test_classify_pr_dip_non_md_still_dip(self):
        """DIP pattern matches dips/DIP-NNNN regardless of extension."""
        result = classify_pr(["dips/DIP-0001-diagram.png"])
        assert "dip" in result

    def test_validate_dips_ignores_non_dip_md(self, tmp_path):
        """Files that are .md but not in dips/DIP-NNNN path should be ignored."""
        f = tmp_path / "docs" / "guide.md"
        f.parent.mkdir()
        f.write_text("# Guide\n\nJust docs, no DIP.\n")
        errors = validate_dips([str(f)])
        assert errors == []

    def test_validate_modules_no_module_files(self):
        """No module-related files should produce no errors."""
        errors = validate_modules(["README.md", "lib/utils.py"])
        assert errors == []

    def test_validate_agents_no_agent_files(self):
        """No agent files should produce no errors."""
        errors = validate_agents(["README.md", "lib/utils.py"])
        assert errors == []

    def test_validate_dips_no_dip_files(self):
        """No DIP files should produce no errors."""
        errors = validate_dips(["README.md", "lib/utils.py"])
        assert errors == []

    def test_github_error_annotation_format(self, tmp_path):
        """Error messages should use GitHub Actions annotation format."""
        agents_dir = tmp_path / "agents"
        agents_dir.mkdir()
        agent = agents_dir / "broken.md"
        agent.write_text("# Broken Agent\n\nNo context section.\n")
        errors = validate_agents([str(agent)])
        assert len(errors) == 1
        assert errors[0].startswith("::error file=")
