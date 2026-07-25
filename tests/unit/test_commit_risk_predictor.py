"""
Phase 2 – ML1 Commit Risk Predictor unit tests.

Tests deterministic helper functions, Git interaction wrappers, function extraction,
risk scoring, and report generation without loading real models or modifying Git state.
"""

import os
import re
import subprocess
from pathlib import Path
from unittest.mock import Mock

import numpy as np
import pandas as pd
import pytest

from ml.commit_risk.commit_risk_predictor import (
    GitCommandError,
    apply_review_required,
    build_commit_metadata,
    build_risk_reason,
    calculate_confidence,
    empty_report_df,
    ensure_git_working_tree,
    extract_changed_functions,
    extract_function_name,
    extract_function_spans,
    extract_top_risky_terms,
    get_changed_cpp_files,
    get_changed_lines_by_file,
    get_risk_level,
    is_within_scan_path,
    model_positive_scores,
    parse_changed_lines_from_diff,
    resolve_diff_range,
    run_git_command,
    aggregate_commit_risk,
)


# ---------------------------------------------------------------------------
# Scenario 1 – Risk thresholds
# ---------------------------------------------------------------------------

class TestGetRiskLevel:
    """Test risk level classification using exact current implementation thresholds."""

    def test_below_medium_threshold_returns_low(self):
        """Value below MEDIUM threshold (50.0) returns LOW."""
        score, level = get_risk_level(0.499, medium_threshold=50.0, high_threshold=80.0)
        assert level == "LOW"
        assert score == 49.9

    def test_at_medium_boundary_returns_medium(self):
        """Value exactly at MEDIUM threshold (50.0) returns MEDIUM."""
        score, level = get_risk_level(0.50, medium_threshold=50.0, high_threshold=80.0)
        assert level == "MEDIUM"
        assert score == 50.0

    def test_below_high_threshold_returns_medium(self):
        """Value below HIGH threshold (80.0) returns MEDIUM."""
        score, level = get_risk_level(0.799, medium_threshold=50.0, high_threshold=80.0)
        assert level == "MEDIUM"
        assert score == 79.9

    def test_at_high_boundary_returns_high(self):
        """Value exactly at HIGH threshold (80.0) returns HIGH."""
        score, level = get_risk_level(0.80, medium_threshold=50.0, high_threshold=80.0)
        assert level == "HIGH"
        assert score == 80.0

    def test_representative_low_value(self):
        """Representative LOW risk value."""
        score, level = get_risk_level(0.25, medium_threshold=50.0, high_threshold=80.0)
        assert level == "LOW"
        assert score == 25.0

    def test_representative_medium_value(self):
        """Representative MEDIUM risk value."""
        score, level = get_risk_level(0.65, medium_threshold=50.0, high_threshold=80.0)
        assert level == "MEDIUM"
        assert score == 65.0

    def test_representative_high_value(self):
        """Representative HIGH risk value."""
        score, level = get_risk_level(0.95, medium_threshold=50.0, high_threshold=80.0)
        assert level == "HIGH"
        assert score == 95.0


# ---------------------------------------------------------------------------
# Scenario 2 – Confidence calculation
# ---------------------------------------------------------------------------

class TestCalculateConfidence:
    """Test confidence calculation from probability scores."""

    def test_low_confidence_near_fifty_percent(self):
        """Probability near 0.5 produces low confidence."""
        confidence = calculate_confidence(0.52)
        assert confidence == 0.04

    def test_medium_confidence(self):
        """Moderate distance from 0.5 produces medium confidence."""
        confidence = calculate_confidence(0.70)
        assert confidence == 0.40

    def test_high_confidence_near_one(self):
        """Probability near 1.0 produces high confidence."""
        confidence = calculate_confidence(0.99)
        assert confidence == 0.98

    def test_high_confidence_near_zero(self):
        """Probability near 0.0 also produces high confidence."""
        confidence = calculate_confidence(0.01)
        assert confidence == 0.98

    def test_exactly_fifty_percent_is_zero_confidence(self):
        """Probability exactly 0.5 produces zero confidence."""
        confidence = calculate_confidence(0.50)
        assert confidence == 0.0


# ---------------------------------------------------------------------------
# Scenario 3 – REVIEW_REQUIRED behaviour
# ---------------------------------------------------------------------------

class TestApplyReviewRequired:
    """Test the REVIEW_REQUIRED override policy."""

    def test_low_with_low_confidence_becomes_review_required(self):
        """LOW risk with confidence below threshold becomes REVIEW_REQUIRED."""
        result = apply_review_required("LOW", confidence=0.3, confidence_threshold=0.5)
        assert result == "REVIEW_REQUIRED"

    def test_medium_with_low_confidence_becomes_review_required(self):
        """MEDIUM risk with confidence below threshold becomes REVIEW_REQUIRED."""
        result = apply_review_required("MEDIUM", confidence=0.4, confidence_threshold=0.5)
        assert result == "REVIEW_REQUIRED"

    def test_high_with_low_confidence_remains_high(self):
        """HIGH risk remains HIGH even with low confidence."""
        result = apply_review_required("HIGH", confidence=0.2, confidence_threshold=0.5)
        assert result == "HIGH"

    def test_low_at_confidence_threshold_remains_low(self):
        """LOW with confidence exactly at threshold remains LOW."""
        result = apply_review_required("LOW", confidence=0.5, confidence_threshold=0.5)
        assert result == "LOW"

    def test_medium_above_confidence_threshold_remains_medium(self):
        """MEDIUM with confidence above threshold remains MEDIUM."""
        result = apply_review_required("MEDIUM", confidence=0.6, confidence_threshold=0.5)
        assert result == "MEDIUM"


# ---------------------------------------------------------------------------
# Scenario 4 – Git command wrapper
# ---------------------------------------------------------------------------

class TestRunGitCommand:
    """Test Git command execution wrapper."""

    def test_successful_command_returns_stdout(self, monkeypatch):
        """Successful Git command returns stripped stdout."""
        def mock_run(cmd, **kwargs):
            result = Mock()
            result.returncode = 0
            result.stdout = "  commit-sha-123  \n"
            result.stderr = ""
            return result

        monkeypatch.setattr(subprocess, "run", mock_run)
        output = run_git_command(["rev-parse", "HEAD"])
        assert output == "commit-sha-123"

    def test_failed_command_raises_git_command_error(self, monkeypatch):
        """Failed Git command raises GitCommandError."""
        def mock_run(cmd, **kwargs):
            result = Mock()
            result.returncode = 128
            result.stdout = ""
            result.stderr = "fatal: not a git repository"
            return result

        monkeypatch.setattr(subprocess, "run", mock_run)
        with pytest.raises(GitCommandError, match="Git command failed"):
            run_git_command(["rev-parse", "HEAD"])

    def test_command_with_context_includes_context_in_error(self, monkeypatch):
        """Command with context includes context message in error."""
        def mock_run(cmd, **kwargs):
            result = Mock()
            result.returncode = 1
            result.stdout = ""
            result.stderr = "error"
            return result

        monkeypatch.setattr(subprocess, "run", mock_run)
        with pytest.raises(GitCommandError, match="Custom context"):
            run_git_command(["status"], context="Custom context")

    def test_subprocess_exception_raises_git_command_error(self, monkeypatch):
        """Subprocess execution exception raises GitCommandError."""
        def mock_run(cmd, **kwargs):
            raise OSError("Command not found")

        monkeypatch.setattr(subprocess, "run", mock_run)
        with pytest.raises(GitCommandError, match="Git command execution failed"):
            run_git_command(["status"])


# ---------------------------------------------------------------------------
# Scenario 5 – Git working-tree validation
# ---------------------------------------------------------------------------

class TestEnsureGitWorkingTree:
    """Test Git repository validation."""

    def test_valid_repository_does_not_raise(self, monkeypatch):
        """Valid Git repository does not raise exception."""
        def mock_run_git(args, context=""):
            return "true"

        import ml.commit_risk.commit_risk_predictor as crp
        monkeypatch.setattr(crp, "run_git_command", mock_run_git)

        try:
            ensure_git_working_tree()
        except Exception as exc:
            pytest.fail(f"ensure_git_working_tree raised unexpectedly: {exc}")

    def test_invalid_repository_raises_runtime_error(self, monkeypatch):
        """Invalid Git repository raises RuntimeError."""
        def mock_run_git(args, context=""):
            return "false"

        import ml.commit_risk.commit_risk_predictor as crp
        monkeypatch.setattr(crp, "run_git_command", mock_run_git)

        with pytest.raises(RuntimeError, match="not inside a Git working tree"):
            ensure_git_working_tree()


# ---------------------------------------------------------------------------
# Scenario 6 – Scan-path filtering
# ---------------------------------------------------------------------------

class TestIsWithinScanPath:
    """Test file path filtering against scan root."""

    def test_file_inside_scan_path_returns_true(self, tmp_path):
        """File inside scan path returns True."""
        repo_root = tmp_path / "repo"
        scan_root = tmp_path / "repo" / "src"
        repo_root.mkdir()
        scan_root.mkdir()

        result = is_within_scan_path(repo_root, scan_root, Path("src/main.c"))
        assert result is True

    def test_file_outside_scan_path_returns_false(self, tmp_path):
        """File outside scan path returns False."""
        repo_root = tmp_path / "repo"
        scan_root = tmp_path / "repo" / "src"
        repo_root.mkdir()
        scan_root.mkdir()
        (repo_root / "test").mkdir()

        result = is_within_scan_path(repo_root, scan_root, Path("test/test.c"))
        assert result is False

    def test_repository_root_scan_path_includes_all_files(self, tmp_path):
        """Scan path at repository root includes all files."""
        repo_root = tmp_path / "repo"
        scan_root = repo_root
        repo_root.mkdir()
        (repo_root / "subdir").mkdir()

        result = is_within_scan_path(repo_root, scan_root, Path("subdir/file.c"))
        assert result is True

    def test_nested_directory_inside_scan_path(self, tmp_path):
        """Nested directory inside scan path returns True."""
        repo_root = tmp_path / "repo"
        scan_root = tmp_path / "repo" / "src"
        repo_root.mkdir()
        scan_root.mkdir()
        (scan_root / "lib").mkdir()

        result = is_within_scan_path(repo_root, scan_root, Path("src/lib/util.c"))
        assert result is True

    def test_similar_prefix_outside_scan_path_returns_false(self, tmp_path):
        """Path with similar prefix but outside scan path returns False."""
        repo_root = tmp_path / "repo"
        scan_root = tmp_path / "repo" / "src"
        repo_root.mkdir()
        scan_root.mkdir()
        (repo_root / "src_test").mkdir()

        result = is_within_scan_path(repo_root, scan_root, Path("src_test/file.c"))
        assert result is False


# ---------------------------------------------------------------------------
# Scenario 7 – Diff-range resolution
# ---------------------------------------------------------------------------

class TestResolveDiffRange:
    """Test diff range resolution from base/head refs."""

    def test_explicit_base_and_head_returns_range(self, monkeypatch):
        """Explicit base and head refs return range string."""
        def mock_run_git(args, context=""):
            return "valid-sha"

        import ml.commit_risk.commit_risk_predictor as crp
        monkeypatch.setattr(crp, "run_git_command", mock_run_git)

        result = resolve_diff_range("main", "feature-branch")
        assert result == "main...feature-branch"

    def test_only_base_provided_raises_value_error(self):
        """Only base ref provided raises ValueError."""
        with pytest.raises(ValueError, match="Both base-ref and head-ref"):
            resolve_diff_range("main", "")

    def test_only_head_provided_raises_value_error(self):
        """Only head ref provided raises ValueError."""
        with pytest.raises(ValueError, match="Both base-ref and head-ref"):
            resolve_diff_range("", "feature-branch")

    def test_no_refs_with_valid_history_returns_default_range(self, monkeypatch):
        """No refs provided with valid history returns HEAD~1...HEAD."""
        def mock_run_git(args, context=""):
            return "valid-sha"

        import ml.commit_risk.commit_risk_predictor as crp
        monkeypatch.setattr(crp, "run_git_command", mock_run_git)

        result = resolve_diff_range("", "")
        assert result == "HEAD~1...HEAD"

    def test_no_refs_with_insufficient_history_raises_value_error(self, monkeypatch):
        """No refs and insufficient Git history raises ValueError."""
        def mock_run_git(args, context=""):
            raise GitCommandError("Unable to resolve HEAD~1")

        import ml.commit_risk.commit_risk_predictor as crp
        monkeypatch.setattr(crp, "run_git_command", mock_run_git)

        with pytest.raises(ValueError, match="Could not resolve a valid diff range"):
            resolve_diff_range("", "")


# ---------------------------------------------------------------------------
# Scenario 8 – Changed C/C++ file detection
# ---------------------------------------------------------------------------

class TestGetChangedCppFiles:
    """Test changed C/C++ file detection from Git diff."""

    def test_detects_c_extension(self, tmp_path, monkeypatch):
        """Detects .c files."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "main.c").touch()

        def mock_run_git(args, context=""):
            return "src/main.c"

        import ml.commit_risk.commit_risk_predictor as crp
        monkeypatch.setattr(crp, "run_git_command", mock_run_git)

        result = get_changed_cpp_files("HEAD~1...HEAD", ".")
        assert "src/main.c" in result

    def test_detects_cpp_extension(self, tmp_path, monkeypatch):
        """Detects .cpp files."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / "app.cpp").touch()

        def mock_run_git(args, context=""):
            return "app.cpp"

        import ml.commit_risk.commit_risk_predictor as crp
        monkeypatch.setattr(crp, "run_git_command", mock_run_git)

        result = get_changed_cpp_files("HEAD~1...HEAD", ".")
        assert "app.cpp" in result

    def test_detects_header_extensions(self, tmp_path, monkeypatch):
        """Detects .h and .hpp files."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / "header.h").touch()
        (tmp_path / "header.hpp").touch()

        def mock_run_git(args, context=""):
            return "header.h\nheader.hpp"

        import ml.commit_risk.commit_risk_predictor as crp
        monkeypatch.setattr(crp, "run_git_command", mock_run_git)

        result = get_changed_cpp_files("HEAD~1...HEAD", ".")
        assert "header.h" in result
        assert "header.hpp" in result

    def test_excludes_unrelated_extensions(self, tmp_path, monkeypatch):
        """Excludes non-C/C++ files."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / "script.py").touch()
        (tmp_path / "readme.md").touch()

        def mock_run_git(args, context=""):
            return "script.py\nreadme.md"

        import ml.commit_risk.commit_risk_predictor as crp
        monkeypatch.setattr(crp, "run_git_command", mock_run_git)

        result = get_changed_cpp_files("HEAD~1...HEAD", ".")
        assert len(result) == 0

    def test_filters_by_scan_path(self, tmp_path, monkeypatch):
        """Filters files by scan path."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / "src").mkdir()
        (tmp_path / "test").mkdir()
        (tmp_path / "src" / "app.c").touch()
        (tmp_path / "test" / "test.c").touch()

        def mock_run_git(args, context=""):
            return "src/app.c\ntest/test.c"

        import ml.commit_risk.commit_risk_predictor as crp
        monkeypatch.setattr(crp, "run_git_command", mock_run_git)

        result = get_changed_cpp_files("HEAD~1...HEAD", "src")
        assert "src/app.c" in result
        assert "test/test.c" not in result

    def test_empty_git_output_returns_empty_list(self, monkeypatch):
        """Empty Git output returns empty list."""
        def mock_run_git(args, context=""):
            return ""

        import ml.commit_risk.commit_risk_predictor as crp
        monkeypatch.setattr(crp, "run_git_command", mock_run_git)

        result = get_changed_cpp_files("HEAD~1...HEAD", ".")
        assert result == []

    def test_excludes_git_directory(self, tmp_path, monkeypatch):
        """Excludes files in .git directory."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".git").mkdir()
        (tmp_path / ".git" / "config.c").touch()

        def mock_run_git(args, context=""):
            return ".git/config.c"

        import ml.commit_risk.commit_risk_predictor as crp
        monkeypatch.setattr(crp, "run_git_command", mock_run_git)

        result = get_changed_cpp_files("HEAD~1...HEAD", ".")
        assert len(result) == 0


# ---------------------------------------------------------------------------
# Scenario 9 – Diff-line parsing
# ---------------------------------------------------------------------------

class TestParseChangedLinesFromDiff:
    """Test unified diff parsing to extract changed line numbers."""

    def test_single_hunk_with_one_line(self):
        """Single hunk with one added line."""
        diff = "@@ -10,3 +10,4 @@ context\n"
        result = parse_changed_lines_from_diff(diff)
        assert 10 in result

    def test_multiple_hunks(self):
        """Multiple hunks in one diff."""
        diff = "@@ -5,2 +5,3 @@\n@@ -20,1 +21,2 @@\n"
        result = parse_changed_lines_from_diff(diff)
        assert 5 in result
        assert 21 in result

    def test_multiline_change(self):
        """Hunk with multiple changed lines."""
        diff = "@@ -10,2 +10,5 @@\n"
        result = parse_changed_lines_from_diff(diff)
        assert 10 in result
        assert 11 in result
        assert 12 in result
        assert 13 in result
        assert 14 in result

    def test_empty_diff_returns_empty_set(self):
        """Empty diff returns empty set."""
        result = parse_changed_lines_from_diff("")
        assert result == set()

    def test_malformed_hunk_is_ignored(self):
        """Malformed hunk header is ignored."""
        diff = "@@ invalid hunk @@\n"
        result = parse_changed_lines_from_diff(diff)
        assert result == set()

    def test_zero_line_count_is_ignored(self):
        """Hunk with zero line count is ignored."""
        diff = "@@ -10,1 +10,0 @@\n"
        result = parse_changed_lines_from_diff(diff)
        assert result == set()


# ---------------------------------------------------------------------------
# Scenario 10 – Changed lines by file
# ---------------------------------------------------------------------------

class TestGetChangedLinesByFile:
    """Test changed line retrieval for multiple files."""

    def test_single_file_with_changes(self, monkeypatch):
        """Single file returns changed lines."""
        def mock_run_git(args, context=""):
            return "@@ -5,1 +5,2 @@\n"

        import ml.commit_risk.commit_risk_predictor as crp
        monkeypatch.setattr(crp, "run_git_command", mock_run_git)

        result = get_changed_lines_by_file("HEAD~1...HEAD", ["src/main.c"])
        assert "src/main.c" in result
        assert 5 in result["src/main.c"]

    def test_multiple_files(self, monkeypatch):
        """Multiple files return separate changed-line sets."""
        call_count = [0]

        def mock_run_git(args, context=""):
            call_count[0] += 1
            if call_count[0] == 1:
                return "@@ -10,1 +10,1 @@\n"
            return "@@ -20,1 +20,1 @@\n"

        import ml.commit_risk.commit_risk_predictor as crp
        monkeypatch.setattr(crp, "run_git_command", mock_run_git)

        result = get_changed_lines_by_file("HEAD~1...HEAD", ["a.c", "b.c"])
        assert 10 in result["a.c"]
        assert 20 in result["b.c"]

    def test_file_with_no_changes_returns_empty_set(self, monkeypatch):
        """File with no parsed changes returns empty set."""
        def mock_run_git(args, context=""):
            return ""

        import ml.commit_risk.commit_risk_predictor as crp
        monkeypatch.setattr(crp, "run_git_command", mock_run_git)

        result = get_changed_lines_by_file("HEAD~1...HEAD", ["empty.c"])
        assert result["empty.c"] == set()


# ---------------------------------------------------------------------------
# Scenario 11 – Function-name extraction
# ---------------------------------------------------------------------------

class TestExtractFunctionName:
    """Test function name extraction from C/C++ signatures."""

    def test_normal_function(self):
        """Normal C function signature."""
        name = extract_function_name("int main")
        assert name == "main"

    def test_namespaced_function(self):
        """C++ namespaced function."""
        name = extract_function_name("void std::vector")
        assert name == "std::vector"

    def test_class_method(self):
        """C++ class method."""
        name = extract_function_name("void MyClass::method")
        assert name == "MyClass::method"

    def test_pointer_return_type(self):
        """Function returning pointer."""
        name = extract_function_name("char* getData")
        assert name == "getData"

    def test_whitespace_handling(self):
        """Function name with trailing whitespace."""
        name = extract_function_name("int process  ")
        assert name == "process"

    def test_input_without_identifier_returns_fallback(self):
        """Input without valid identifier returns anonymous_function."""
        # Test with input that has no valid identifier pattern
        name = extract_function_name("@#$%^&*()")
        assert name == "anonymous_function"


# ---------------------------------------------------------------------------
# Scenario 12 – Function-span extraction
# ---------------------------------------------------------------------------

class TestExtractFunctionSpans:
    """Test function span extraction from C/C++ source code."""

    def test_single_function(self):
        """Single function in source."""
        source = """
int add(int a, int b) {
    return a + b;
}
"""
        functions = extract_function_spans(source)
        assert len(functions) == 1
        assert functions[0]["function_name"] == "add"
        assert functions[0]["start_line"] == 2
        assert functions[0]["end_line"] == 4

    def test_multiple_functions(self):
        """Multiple functions in source."""
        source = """
void foo() {
}

int bar() {
    return 0;
}
"""
        functions = extract_function_spans(source)
        assert len(functions) == 2
        assert functions[0]["function_name"] == "foo"
        assert functions[1]["function_name"] == "bar"

    def test_nested_braces(self):
        """Function with nested braces."""
        source = """
void process() {
    if (cond) {
        action();
    }
}
"""
        functions = extract_function_spans(source)
        assert len(functions) == 1
        assert functions[0]["function_name"] == "process"
        assert functions[0]["end_line"] == 6

    def test_no_functions_returns_empty_list(self):
        """Source with no functions returns empty list."""
        source = "int x = 5;\n"
        functions = extract_function_spans(source)
        assert functions == []

    def test_incomplete_function_is_ignored(self):
        """Incomplete function without closing brace is ignored."""
        source = """
void incomplete() {
    return;
"""
        functions = extract_function_spans(source)
        assert functions == []

    def test_control_statement_not_treated_as_function(self):
        """Control statement is not treated as function."""
        source = """
void real_function() {
    if (condition) {
        action();
    }
}
"""
        functions = extract_function_spans(source)
        assert len(functions) == 1
        assert functions[0]["function_name"] == "real_function"


# ---------------------------------------------------------------------------
# Scenario 13 – Changed-function extraction
# ---------------------------------------------------------------------------

class TestExtractChangedFunctions:
    """Test changed function extraction from files."""

    def test_change_inside_function(self, tmp_path):
        """Changed line inside function returns that function."""
        source_file = tmp_path / "test.c"
        source_file.write_text("""
void target() {
    modified_line();
}
""")
        result = extract_changed_functions(tmp_path, Path("test.c"), changed_lines={3})
        assert len(result) == 1
        assert result[0]["function_name"] == "target"
        assert result[0]["fallback_used"] is False

    def test_changes_across_two_functions(self, tmp_path):
        """Changes in two functions return both."""
        source_file = tmp_path / "test.c"
        source_file.write_text("""
void first() {
    line_a();
}

void second() {
    line_b();
}
""")
        result = extract_changed_functions(tmp_path, Path("test.c"), changed_lines={3, 7})
        assert len(result) == 2
        assert result[0]["function_name"] == "first"
        assert result[1]["function_name"] == "second"

    def test_change_outside_function_uses_fallback(self, tmp_path):
        """Changed line outside detected function uses fallback."""
        source_file = tmp_path / "test.c"
        source_file.write_text("int global_var = 5;\n")
        result = extract_changed_functions(tmp_path, Path("test.c"), changed_lines={1})
        assert len(result) == 1
        assert result[0]["function_name"] == "__FILE_FALLBACK__"
        assert result[0]["fallback_used"] is True

    def test_empty_changed_lines_uses_fallback(self, tmp_path):
        """Empty changed-line set uses fallback."""
        source_file = tmp_path / "test.c"
        source_file.write_text("void func() {}\n")
        result = extract_changed_functions(tmp_path, Path("test.c"), changed_lines=set())
        assert len(result) == 1
        assert result[0]["fallback_used"] is True

    def test_empty_source_uses_fallback(self, tmp_path):
        """Empty source file uses fallback."""
        source_file = tmp_path / "test.c"
        source_file.write_text("")
        result = extract_changed_functions(tmp_path, Path("test.c"), changed_lines={1})
        assert len(result) == 1
        assert result[0]["fallback_used"] is True


# ---------------------------------------------------------------------------
# Scenario 14 – Model-score handling
# ---------------------------------------------------------------------------

class TestModelPositiveScores:
    """Test model score extraction without loading real models."""

    def test_predict_proba_model(self):
        """Model with predict_proba returns positive class probabilities."""
        model = Mock()
        model.predict_proba = Mock(return_value=np.array([[0.3, 0.7], [0.6, 0.4]]))
        features = np.array([[1, 2], [3, 4]])

        scores = model_positive_scores(model, features)
        assert list(scores) == [0.7, 0.4]

    def test_decision_function_model(self):
        """Model with decision_function applies sigmoid transformation."""
        model = Mock()
        model.predict_proba = None
        model.decision_function = Mock(return_value=np.array([0.0, 2.0]))
        del model.predict_proba
        features = np.array([[1, 2], [3, 4]])

        scores = model_positive_scores(model, features)
        assert abs(scores[0] - 0.5) < 0.01
        assert scores[1] > 0.8

    def test_predict_only_model(self):
        """Model with only predict returns predictions as floats."""
        model = Mock()
        del model.predict_proba
        del model.decision_function
        model.predict = Mock(return_value=np.array([0, 1]))
        features = np.array([[1, 2], [3, 4]])

        scores = model_positive_scores(model, features)
        assert list(scores) == [0.0, 1.0]


# ---------------------------------------------------------------------------
# Scenario 15 – Risk-reason generation
# ---------------------------------------------------------------------------

class TestExtractTopRiskyTerms:
    """Test risky term extraction from function code."""

    def test_finds_risky_terms(self):
        """Finds risky terms in function code."""
        code = "char* result = strcpy(buffer, input);"
        terms = extract_top_risky_terms(code)
        assert "strcpy" in terms
        assert "buffer" in terms

    def test_no_risky_terms_returns_empty(self):
        """Function with no risky terms returns empty list."""
        code = "int add(int a, int b) { return a + b; }"
        terms = extract_top_risky_terms(code)
        assert terms == []

    def test_case_insensitive_matching(self):
        """Term matching is case-insensitive."""
        code = "MALLOC(size); STRCPY(dest, src);"
        terms = extract_top_risky_terms(code)
        assert "malloc" in terms
        assert "strcpy" in terms

    def test_returns_at_most_five_terms(self):
        """Returns at most five terms."""
        code = "strcpy strcat sprintf malloc calloc realloc free buffer overflow"
        terms = extract_top_risky_terms(code)
        assert len(terms) <= 5


class TestBuildRiskReason:
    """Test risk reason message generation."""

    def test_review_required_reason(self):
        """REVIEW_REQUIRED generates confidence-based reason."""
        reason = build_risk_reason("REVIEW_REQUIRED", ["strcpy"], False, 0.3, 0.5)
        assert "REVIEW_REQUIRED" in reason
        assert "confidence" in reason
        assert "0.3" in reason

    def test_high_with_terms(self):
        """HIGH with terms mentions the terms."""
        reason = build_risk_reason("HIGH", ["malloc", "free"], False, 0.9, 0.5)
        assert "HIGH" in reason
        assert "malloc" in reason

    def test_medium_with_terms(self):
        """MEDIUM with terms mentions the terms."""
        reason = build_risk_reason("MEDIUM", ["buffer"], False, 0.7, 0.5)
        assert "MEDIUM" in reason
        assert "buffer" in reason

    def test_low_without_terms(self):
        """LOW without terms uses default message."""
        reason = build_risk_reason("LOW", [], False, 0.8, 0.5)
        assert "LOW" in reason
        assert "no strong vulnerable pattern" in reason.lower()

    def test_fallback_used_appends_note(self):
        """Fallback used appends note to reason."""
        reason = build_risk_reason("LOW", [], True, 0.8, 0.5)
        assert "fallback" in reason.lower()

    def test_high_without_terms(self):
        """HIGH without terms uses model confidence message."""
        reason = build_risk_reason("HIGH", [], False, 0.9, 0.5)
        assert "HIGH" in reason
        assert "model confidence" in reason.lower()
        assert "vulnerable code patterns" in reason.lower()

    def test_medium_without_terms(self):
        """MEDIUM without terms uses model confidence message."""
        reason = build_risk_reason("MEDIUM", [], False, 0.7, 0.5)
        assert "MEDIUM" in reason
        assert "model confidence" in reason.lower()
        assert "potentially risky" in reason.lower()


# ---------------------------------------------------------------------------
# Scenario 16 – Commit-level aggregation
# ---------------------------------------------------------------------------

class TestAggregateCommitRisk:
    """Test commit-level risk aggregation from function results."""

    def test_empty_results_returns_skipped(self):
        """Empty function results return SKIPPED."""
        result = aggregate_commit_risk([])
        assert result == "SKIPPED"

    def test_all_low_returns_low(self):
        """All LOW results return LOW."""
        result = aggregate_commit_risk(["LOW", "LOW", "LOW"])
        assert result == "LOW"

    def test_low_and_medium_returns_medium(self):
        """LOW and MEDIUM results return MEDIUM."""
        result = aggregate_commit_risk(["LOW", "MEDIUM", "LOW"])
        assert result == "MEDIUM"

    def test_one_high_returns_high(self):
        """One HIGH result returns HIGH."""
        result = aggregate_commit_risk(["LOW", "MEDIUM", "HIGH"])
        assert result == "HIGH"

    def test_multiple_high_returns_high(self):
        """Multiple HIGH results return HIGH."""
        result = aggregate_commit_risk(["HIGH", "HIGH"])
        assert result == "HIGH"

    def test_review_required_without_high_returns_review_required(self):
        """REVIEW_REQUIRED without HIGH returns REVIEW_REQUIRED."""
        result = aggregate_commit_risk(["LOW", "REVIEW_REQUIRED", "MEDIUM"])
        assert result == "REVIEW_REQUIRED"

    def test_high_overrides_review_required(self):
        """HIGH overrides REVIEW_REQUIRED."""
        result = aggregate_commit_risk(["REVIEW_REQUIRED", "HIGH"])
        assert result == "HIGH"


# ---------------------------------------------------------------------------
# Scenario 17 – Commit metadata
# ---------------------------------------------------------------------------

class TestBuildCommitMetadata:
    """Test commit metadata collection from arguments and environment."""

    def test_uses_explicit_arguments(self, monkeypatch):
        """Uses explicit argument values when provided."""
        args = Mock()
        args.commit_sha = "abc123"
        args.branch = "main"
        args.event_type = "push"
        args.author = "developer"
        args.base_ref = "base"
        args.head_ref = "head"

        metadata = build_commit_metadata(args)
        assert metadata["commit_sha"] == "abc123"
        assert metadata["branch"] == "main"
        assert metadata["event_type"] == "push"
        assert metadata["author"] == "developer"

    def test_falls_back_to_environment(self, monkeypatch):
        """Falls back to environment variables when arguments are empty."""
        monkeypatch.setenv("GITHUB_SHA", "env-sha")
        monkeypatch.setenv("GITHUB_REF_NAME", "env-branch")
        monkeypatch.setenv("GITHUB_EVENT_NAME", "pull_request")
        monkeypatch.setenv("GITHUB_ACTOR", "env-author")

        args = Mock()
        args.commit_sha = ""
        args.branch = ""
        args.event_type = ""
        args.author = ""
        args.base_ref = ""
        args.head_ref = ""

        metadata = build_commit_metadata(args)
        assert metadata["commit_sha"] == "env-sha"
        assert metadata["branch"] == "env-branch"
        assert metadata["event_type"] == "pull_request"
        assert metadata["author"] == "env-author"

    def test_falls_back_to_git_commands(self, monkeypatch):
        """Falls back to Git commands when environment is empty."""
        for var in ["GITHUB_SHA", "GITHUB_REF_NAME", "GITHUB_EVENT_NAME", "GITHUB_ACTOR", "GITHUB_BASE_REF", "GITHUB_HEAD_REF"]:
            monkeypatch.delenv(var, raising=False)

        call_count = [0]

        def mock_run_git(args, context=""):
            call_count[0] += 1
            if call_count[0] == 1:
                return "git-sha"
            return "git-author"

        import ml.commit_risk.commit_risk_predictor as crp
        monkeypatch.setattr(crp, "run_git_command", mock_run_git)

        args = Mock()
        args.commit_sha = ""
        args.branch = ""
        args.event_type = ""
        args.author = ""
        args.base_ref = ""
        args.head_ref = ""

        metadata = build_commit_metadata(args)
        assert metadata["commit_sha"] == "git-sha"
        assert metadata["author"] == "git-author"


# ---------------------------------------------------------------------------
# Scenario 18 – Empty report schema
# ---------------------------------------------------------------------------

class TestEmptyReportDf:
    """Test empty report DataFrame schema."""

    def test_returns_dataframe(self):
        """Returns a pandas DataFrame."""
        df = empty_report_df()
        assert isinstance(df, pd.DataFrame)

    def test_contains_expected_columns(self):
        """Contains all expected report columns."""
        df = empty_report_df()
        expected = {
            "commit_sha", "branch", "event_type", "author", "base_ref", "head_ref",
            "file_path", "function_name", "start_line", "end_line",
            "risk_score", "risk_level", "confidence", "review_confidence_threshold",
            "top_risky_terms", "risk_reason",
            "vectorization_time_ms", "model_inference_time_ms", "total_prediction_runtime_ms"
        }
        assert expected.issubset(set(df.columns))

    def test_contains_zero_rows(self):
        """Contains zero rows."""
        df = empty_report_df()
        assert len(df) == 0

    def test_column_order_is_deterministic(self):
        """Column order is deterministic across calls."""
        df1 = empty_report_df()
        df2 = empty_report_df()
        assert list(df1.columns) == list(df2.columns)
