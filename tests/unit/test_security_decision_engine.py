"""
Phase 1 – Security Decision Engine unit tests.

Scenarios covered (derived directly from the production implementation):
 1.  Clean ML1, Cppcheck, Clang and ML3 results  → PASS
 2.  ML1 HIGH risk                                → BLOCK
 3.  Cppcheck HIGH priority alert                 → BLOCK
 4.  Clang HIGH priority alert                    → BLOCK
 5.  Multiple blocking sources                    → BLOCK
 6.  ML1 REVIEW_REQUIRED (no blocking)            → REVIEW
 7.  ML1 MEDIUM (no blocking)                     → REVIEW
 8.  ML3 ANOMALOUS / malformed / FAILED           → REVIEW
 9.  BLOCK takes precedence over REVIEW           → BLOCK
10.  All empty DataFrames                         → PASS
11.  Missing report file (load_report)            → empty DataFrame
12.  Malformed / header-only file (load_report)   → empty DataFrame
13.  build_alert_summary bounded output
14.  build_commit_risk_summary bounded output
15.  get_anomaly_summary: normal and anomalous rows
16.  write_decision: creates output file with required columns
"""

import pandas as pd
import pytest

import ml.decision_engine.security_decision_engine as sde_module
from ml.decision_engine.security_decision_engine import (
    build_alert_summary,
    build_commit_risk_summary,
    calculate_decision,
    get_anomaly_summary,
    load_report,
    write_decision,
)


# ---------------------------------------------------------------------------
# Inline builder helpers
# ---------------------------------------------------------------------------

def _alert_df(priority, tool="cppcheck", n=1):
    """Create an alert DataFrame with n rows of the given priority."""
    return pd.DataFrame([
        {
            "priority": priority,
            "tool": tool,
            "file": f"src/file{i}.c",
            "line": i * 10,
            "alert_id": f"A{i}",
            "message": f"msg {i}",
        }
        for i in range(1, n + 1)
    ])


def _commit_df(risk_level, n=1):
    """Create a commit-risk DataFrame with n rows of the given risk_level."""
    return pd.DataFrame([
        {
            "risk_level": risk_level,
            "file_path": f"src/file{i}.py",
            "risk_score": round(0.1 * i, 2),
        }
        for i in range(1, n + 1)
    ])


def _anomaly_df(status, score=-0.1, reason=None):
    """Create a one-row anomaly DataFrame. Omit 'reason' to test the fallback path."""
    row = {"anomaly_status": status, "anomaly_score": score}
    if reason is not None:
        row["reason"] = reason
    return pd.DataFrame([row])


# ---------------------------------------------------------------------------
# Scenario 1 – Clean results → PASS
# ---------------------------------------------------------------------------

class TestCleanResultsPass:
    def test_all_low_risk_produces_pass(
        self, clean_commit_df, clean_alert_df, clean_anomaly_df
    ):
        result = calculate_decision(
            clean_commit_df, clean_alert_df, clean_alert_df, clean_anomaly_df
        )
        assert result["decision"] == "PASS"

    def test_all_low_risk_reason_mentions_low_findings(
        self, clean_commit_df, clean_alert_df, clean_anomaly_df
    ):
        result = calculate_decision(
            clean_commit_df, clean_alert_df, clean_alert_df, clean_anomaly_df
        )
        assert "low" in result["reason"].lower()


# ---------------------------------------------------------------------------
# Scenario 2 – ML1 HIGH risk → BLOCK
# ---------------------------------------------------------------------------

class TestML1HighRiskBlock:
    def test_commit_high_risk_produces_block(self, empty_df, clean_anomaly_df):
        result = calculate_decision(
            _commit_df("HIGH"), empty_df, empty_df, clean_anomaly_df
        )
        assert result["decision"] == "BLOCK"

    def test_commit_high_count_is_one(self, empty_df, clean_anomaly_df):
        result = calculate_decision(
            _commit_df("HIGH"), empty_df, empty_df, clean_anomaly_df
        )
        assert result["commit_high_count"] == 1


# ---------------------------------------------------------------------------
# Scenario 3 – Cppcheck HIGH priority → BLOCK
# ---------------------------------------------------------------------------

class TestCppcheckHighPriorityBlock:
    def test_cppcheck_high_alert_produces_block(self, empty_df, clean_anomaly_df):
        result = calculate_decision(
            empty_df, _alert_df("HIGH", tool="cppcheck"), empty_df, clean_anomaly_df
        )
        assert result["decision"] == "BLOCK"

    def test_cppcheck_high_alert_count_is_one(self, empty_df, clean_anomaly_df):
        result = calculate_decision(
            empty_df, _alert_df("HIGH", tool="cppcheck"), empty_df, clean_anomaly_df
        )
        assert result["alert_high_count"] == 1


# ---------------------------------------------------------------------------
# Scenario 4 – Clang HIGH priority → BLOCK
# ---------------------------------------------------------------------------

class TestClangHighPriorityBlock:
    def test_clang_high_alert_produces_block(self, empty_df, clean_anomaly_df):
        result = calculate_decision(
            empty_df, empty_df, _alert_df("HIGH", tool="clang"), clean_anomaly_df
        )
        assert result["decision"] == "BLOCK"

    def test_clang_high_alert_count_is_one(self, empty_df, clean_anomaly_df):
        result = calculate_decision(
            empty_df, empty_df, _alert_df("HIGH", tool="clang"), clean_anomaly_df
        )
        assert result["alert_high_count"] == 1


# ---------------------------------------------------------------------------
# Scenario 5 – Multiple blocking sources → BLOCK
# ---------------------------------------------------------------------------

class TestMultipleBlockingSources:
    def test_ml1_cppcheck_and_clang_all_high_produces_block(
        self, clean_anomaly_df
    ):
        result = calculate_decision(
            _commit_df("HIGH"),
            _alert_df("HIGH", tool="cppcheck"),
            _alert_df("HIGH", tool="clang"),
            clean_anomaly_df,
        )
        assert result["decision"] == "BLOCK"

    def test_combined_high_counts_are_correct(self, clean_anomaly_df):
        result = calculate_decision(
            _commit_df("HIGH"),
            _alert_df("HIGH", tool="cppcheck"),
            _alert_df("HIGH", tool="clang"),
            clean_anomaly_df,
        )
        assert result["commit_high_count"] == 1
        assert result["alert_high_count"] == 2


# ---------------------------------------------------------------------------
# Scenario 6 – ML1 REVIEW_REQUIRED (no blocking) → REVIEW
# ---------------------------------------------------------------------------

class TestML1ReviewRequired:
    def test_review_required_produces_review(self, empty_df, clean_anomaly_df):
        result = calculate_decision(
            _commit_df("REVIEW_REQUIRED"), empty_df, empty_df, clean_anomaly_df
        )
        assert result["decision"] == "REVIEW"

    def test_review_required_reason_is_set(self, empty_df, clean_anomaly_df):
        result = calculate_decision(
            _commit_df("REVIEW_REQUIRED"), empty_df, empty_df, clean_anomaly_df
        )
        assert "review" in result["reason"].lower()

    def test_review_required_count_is_one(self, empty_df, clean_anomaly_df):
        result = calculate_decision(
            _commit_df("REVIEW_REQUIRED"), empty_df, empty_df, clean_anomaly_df
        )
        assert result["commit_review_required_count"] == 1


# ---------------------------------------------------------------------------
# Scenario 7 – ML1 MEDIUM (no blocking) → REVIEW
# ---------------------------------------------------------------------------

class TestML1MediumRisk:
    def test_medium_commit_risk_produces_review(self, empty_df, clean_anomaly_df):
        result = calculate_decision(
            _commit_df("MEDIUM"), empty_df, empty_df, clean_anomaly_df
        )
        assert result["decision"] == "REVIEW"

    def test_medium_commit_count_is_one(self, empty_df, clean_anomaly_df):
        result = calculate_decision(
            _commit_df("MEDIUM"), empty_df, empty_df, clean_anomaly_df
        )
        assert result["commit_medium_count"] == 1


# ---------------------------------------------------------------------------
# Scenario 8 – ML3 anomaly / malformed / failed (no blocking) → REVIEW
# ---------------------------------------------------------------------------

class TestML3AnomalyReview:
    def test_anomalous_status_produces_review(self, empty_df):
        result = calculate_decision(
            empty_df, empty_df, empty_df,
            _anomaly_df("ANOMALOUS", score=0.9, reason="Spike detected"),
        )
        assert result["decision"] == "REVIEW"

    def test_anomalous_reason_is_set(self, empty_df):
        result = calculate_decision(
            empty_df, empty_df, empty_df,
            _anomaly_df("ANOMALOUS", score=0.9, reason="Spike detected"),
        )
        assert "anomal" in result["reason"].lower()

    def test_ml3_failed_status_produces_review(self, empty_df):
        """anomaly_status=='FAILED' triggers the ml3_failed branch → REVIEW."""
        result = calculate_decision(
            empty_df, empty_df, empty_df,
            _anomaly_df("FAILED", score=0.0, reason="Runtime error"),
        )
        assert result["decision"] == "REVIEW"

    def test_ml3_not_available_with_missing_keyword_produces_review(self, empty_df):
        """NOT_AVAILABLE + 'MISSING' in reason triggers malformed_or_schema_not_available → REVIEW."""
        anomaly_df = pd.DataFrame([{
            "anomaly_status": "NOT_AVAILABLE",
            "anomaly_score": "",
            "reason": "MISSING upstream metric columns",
        }])
        result = calculate_decision(empty_df, empty_df, empty_df, anomaly_df)
        assert result["decision"] == "REVIEW"


# ---------------------------------------------------------------------------
# Scenario 9 – BLOCK takes precedence over REVIEW
# ---------------------------------------------------------------------------

class TestBlockPrecedenceOverReview:
    def test_high_commit_risk_with_review_required_produces_block(
        self, empty_df, clean_anomaly_df
    ):
        """HIGH and REVIEW_REQUIRED both present; BLOCK condition is checked first."""
        commit_df = pd.DataFrame([
            {"risk_level": "HIGH", "file_path": "src/a.py", "risk_score": 0.9},
            {"risk_level": "REVIEW_REQUIRED", "file_path": "src/b.py", "risk_score": 0.5},
        ])
        result = calculate_decision(commit_df, empty_df, empty_df, clean_anomaly_df)
        assert result["decision"] == "BLOCK"

    def test_high_alert_with_anomalous_ml3_produces_block(self, empty_df):
        """HIGH alert and ANOMALOUS ML3 present; BLOCK condition wins."""
        result = calculate_decision(
            empty_df,
            _alert_df("HIGH", tool="cppcheck"),
            empty_df,
            _anomaly_df("ANOMALOUS", score=0.9, reason="Spike"),
        )
        assert result["decision"] == "BLOCK"


# ---------------------------------------------------------------------------
# Scenario 10 – All empty DataFrames → PASS (implementation-defined)
# ---------------------------------------------------------------------------

class TestEmptyReportsProducePass:
    def test_all_empty_dataframes_produce_pass(self, empty_df):
        """
        When every report is empty, get_anomaly_summary returns NOT_AVAILABLE
        with reason 'ML3 anomaly report not available'.  That reason contains
        none of the schema-mismatch keywords, so the decision is PASS.
        """
        result = calculate_decision(empty_df, empty_df, empty_df, empty_df)
        assert result["decision"] == "PASS"

    def test_all_empty_reason_indicates_no_findings(self, empty_df):
        result = calculate_decision(empty_df, empty_df, empty_df, empty_df)
        assert "no" in result["reason"].lower()

    def test_all_counts_are_zero(self, empty_df):
        result = calculate_decision(empty_df, empty_df, empty_df, empty_df)
        assert result["commit_high_count"] == 0
        assert result["alert_high_count"] == 0
        assert result["commit_review_required_count"] == 0


# ---------------------------------------------------------------------------
# Scenario 11 – Missing report file → load_report returns empty DataFrame
# ---------------------------------------------------------------------------

class TestLoadReportMissingFile:
    def test_nonexistent_path_returns_empty_dataframe(self, tmp_path):
        missing = str(tmp_path / "does_not_exist.csv")
        result = load_report(missing, "TestReport")
        assert isinstance(result, pd.DataFrame)
        assert result.empty

    def test_missing_file_does_not_raise(self, tmp_path):
        missing = str(tmp_path / "nonexistent.csv")
        try:
            load_report(missing, "TestReport")
        except Exception as exc:
            pytest.fail(f"load_report raised unexpectedly: {exc}")


# ---------------------------------------------------------------------------
# Scenario 12 – Malformed / header-only / wrong-column files → existing behaviour
# ---------------------------------------------------------------------------

class TestLoadReportMalformedFile:
    def test_unclosable_quote_file_returns_empty_dataframe(self, tmp_path):
        """
        Unclosed CSV quote causes pandas.errors.ParserError.
        load_report catches all Exception types and returns pd.DataFrame().
        """
        bad_file = tmp_path / "bad.csv"
        bad_file.write_text('"col1","col2\nval1,val2\n')
        result = load_report(str(bad_file), "BadReport")
        assert isinstance(result, pd.DataFrame)
        assert result.empty

    def test_header_only_csv_returns_empty_dataframe(self, tmp_path):
        """
        A CSV with a header row and no data rows is treated as empty by pandas;
        load_report returns pd.DataFrame() via the df.empty branch.
        """
        csv_file = tmp_path / "header_only.csv"
        csv_file.write_text("priority,tool,file,line,alert_id,message\n")
        result = load_report(str(csv_file), "HeaderOnly")
        assert result.empty

    def test_valid_csv_with_wrong_columns_is_returned_as_is(self, tmp_path):
        """
        load_report does not validate column names; a parseable CSV with
        unexpected columns is returned so calculate_decision receives it
        (existing behaviour – no schema enforcement in load_report).
        """
        csv_file = tmp_path / "wrong_cols.csv"
        csv_file.write_text("col_a,col_b\n1,2\n3,4\n")
        result = load_report(str(csv_file), "WrongColsReport")
        assert not result.empty
        assert list(result.columns) == ["col_a", "col_b"]


# ---------------------------------------------------------------------------
# Scenario 13 – build_alert_summary: bounded, deterministic output
# ---------------------------------------------------------------------------

class TestBuildAlertSummary:
    def test_empty_df_returns_empty_string(self, empty_df):
        assert build_alert_summary(empty_df, "HIGH") == ""

    def test_no_matching_priority_returns_empty_string(self):
        assert build_alert_summary(_alert_df("LOW"), "HIGH") == ""

    def test_returns_at_most_default_max_items(self):
        summary = build_alert_summary(_alert_df("HIGH", n=10), "HIGH")
        assert len(summary.split(" ; ")) <= 5

    def test_exactly_max_items_returned_when_more_rows_exist(self):
        summary = build_alert_summary(_alert_df("HIGH", n=8), "HIGH", max_items=3)
        assert len(summary.split(" ; ")) == 3

    def test_summary_contains_tool_name(self):
        summary = build_alert_summary(_alert_df("HIGH", tool="cppcheck"), "HIGH")
        assert "cppcheck" in summary

    def test_summary_contains_alert_id(self):
        summary = build_alert_summary(_alert_df("HIGH"), "HIGH")
        assert "A1" in summary

    def test_summary_contains_file_colon_line(self):
        summary = build_alert_summary(_alert_df("HIGH"), "HIGH")
        assert "src/file1.c:10" in summary


# ---------------------------------------------------------------------------
# Scenario 14 – build_commit_risk_summary: bounded, deterministic output
# ---------------------------------------------------------------------------

class TestBuildCommitRiskSummary:
    def test_empty_df_returns_empty_string(self, empty_df):
        assert build_commit_risk_summary(empty_df, "HIGH") == ""

    def test_no_matching_level_returns_empty_string(self):
        assert build_commit_risk_summary(_commit_df("LOW"), "HIGH") == ""

    def test_returns_at_most_default_max_items(self):
        summary = build_commit_risk_summary(_commit_df("HIGH", n=10), "HIGH")
        assert len(summary.split(" ; ")) <= 5

    def test_exactly_max_items_returned_when_more_rows_exist(self):
        summary = build_commit_risk_summary(_commit_df("HIGH", n=8), "HIGH", max_items=3)
        assert len(summary.split(" ; ")) == 3

    def test_summary_contains_commit_risk_prefix(self):
        summary = build_commit_risk_summary(_commit_df("HIGH"), "HIGH")
        assert "commit-risk" in summary

    def test_summary_contains_file_path(self):
        summary = build_commit_risk_summary(_commit_df("HIGH"), "HIGH")
        assert "src/file1.py" in summary


# ---------------------------------------------------------------------------
# Scenario 15 – get_anomaly_summary: normal and anomalous rows
# ---------------------------------------------------------------------------

class TestGetAnomalySummary:
    def test_empty_df_returns_not_available_status(self, empty_df):
        assert get_anomaly_summary(empty_df)["anomaly_status"] == "NOT_AVAILABLE"

    def test_empty_df_returns_empty_score(self, empty_df):
        assert get_anomaly_summary(empty_df)["anomaly_score"] == ""

    def test_empty_df_reason_mentions_not_available(self, empty_df):
        reason = get_anomaly_summary(empty_df)["anomaly_reason"].lower()
        assert "not available" in reason

    def test_normal_row_returns_normal_status(self):
        result = get_anomaly_summary(_anomaly_df("NORMAL", score=-0.5, reason="All fine"))
        assert result["anomaly_status"] == "NORMAL"

    def test_anomalous_row_returns_anomalous_status(self):
        result = get_anomaly_summary(_anomaly_df("ANOMALOUS", score=0.9, reason="Spike"))
        assert result["anomaly_status"] == "ANOMALOUS"

    def test_score_is_preserved(self):
        result = get_anomaly_summary(_anomaly_df("ANOMALOUS", score=0.85))
        assert result["anomaly_score"] == 0.85

    def test_reason_field_used_when_present(self):
        result = get_anomaly_summary(_anomaly_df("ANOMALOUS", reason="Custom reason text"))
        assert result["anomaly_reason"] == "Custom reason text"

    def test_reason_fallback_built_when_column_absent(self):
        """When the 'reason' column is not present, a fallback string is built."""
        df = pd.DataFrame([{"anomaly_status": "ANOMALOUS", "anomaly_score": 0.7}])
        result = get_anomaly_summary(df)
        assert "ANOMALOUS" in result["anomaly_reason"]


# ---------------------------------------------------------------------------
# Scenario 16 – write_decision: creates output file with required columns
# ---------------------------------------------------------------------------

_EXPECTED_COLUMNS = {
    "decision", "reason",
    "commit_high_count", "commit_review_required_count",
    "commit_medium_count", "commit_low_count",
    "alert_high_count", "alert_medium_count", "alert_low_count",
    "anomaly_status", "anomaly_score", "anomaly_reason",
    "commit_high_issues", "commit_review_required_issues",
    "commit_medium_issues", "commit_low_issues",
    "alert_high_issues", "alert_medium_issues", "alert_low_issues",
}


def _sample_decision_result(decision="PASS"):
    return {
        "decision": decision,
        "reason": "No commit risk, security alerts, or anomaly detected",
        "commit_high_count": 0,
        "commit_review_required_count": 0,
        "commit_medium_count": 0,
        "commit_low_count": 0,
        "alert_high_count": 0,
        "alert_medium_count": 0,
        "alert_low_count": 0,
        "anomaly_status": "NOT_AVAILABLE",
        "anomaly_score": "",
        "anomaly_reason": "ML3 anomaly report not available",
        "commit_high_issues": "",
        "commit_review_required_issues": "",
        "commit_medium_issues": "",
        "commit_low_issues": "",
        "alert_high_issues": "",
        "alert_medium_issues": "",
        "alert_low_issues": "",
    }


class TestWriteDecision:
    def test_write_decision_creates_csv_file(self, tmp_path, monkeypatch):
        """
        monkeypatch.chdir redirects all relative paths (os.makedirs and OUTPUT_FILE)
        to tmp_path so no write occurs in the real reports/ directory.
        """
        monkeypatch.chdir(tmp_path)
        write_decision(_sample_decision_result())
        expected = tmp_path / "reports" / "final_decision" / "security_decision.csv"
        assert expected.exists()

    def test_write_decision_csv_has_required_columns(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        write_decision(_sample_decision_result())
        df = pd.read_csv(
            tmp_path / "reports" / "final_decision" / "security_decision.csv"
        )
        assert _EXPECTED_COLUMNS.issubset(set(df.columns))

    def test_write_decision_preserves_decision_value(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        write_decision(_sample_decision_result(decision="BLOCK"))
        df = pd.read_csv(
            tmp_path / "reports" / "final_decision" / "security_decision.csv"
        )
        assert df.iloc[0]["decision"] == "BLOCK"


# ---------------------------------------------------------------------------
# Part 1.A – Missing required columns: document current KeyError behaviour
# ---------------------------------------------------------------------------

class TestMissingRequiredColumns:
    """
    Document the current production behaviour when required columns are absent.
    The existing implementation does not validate schemas before accessing columns;
    missing columns raise KeyError from pandas .eq() or dictionary .get() calls.
    """

    def test_ml1_missing_risk_level_column_raises_keyerror(self, empty_df, clean_anomaly_df):
        """ML1 DataFrame missing 'risk_level' triggers KeyError in calculate_decision."""
        commit_df = pd.DataFrame([{"file_path": "src/foo.py", "risk_score": 0.8}])
        with pytest.raises(KeyError, match="risk_level"):
            calculate_decision(commit_df, empty_df, empty_df, clean_anomaly_df)

    def test_cppcheck_missing_priority_column_raises_keyerror(self, empty_df, clean_anomaly_df):
        """Cppcheck DataFrame missing 'priority' triggers KeyError when counting alerts."""
        cppcheck_df = pd.DataFrame([{"tool": "cppcheck", "file": "src/foo.c"}])
        with pytest.raises(KeyError, match="priority"):
            calculate_decision(empty_df, cppcheck_df, empty_df, clean_anomaly_df)

    def test_clang_missing_priority_column_raises_keyerror(self, empty_df, clean_anomaly_df):
        """Clang DataFrame missing 'priority' triggers KeyError when counting alerts."""
        clang_df = pd.DataFrame([{"tool": "clang", "file": "src/bar.c"}])
        with pytest.raises(KeyError, match="priority"):
            calculate_decision(empty_df, empty_df, clang_df, clean_anomaly_df)

    def test_ml3_missing_status_column_returns_not_available_default(self, empty_df):
        """
        ML3 DataFrame missing 'anomaly_status' is handled gracefully by get_anomaly_summary.
        The function uses row.get() with a default value, returning "NOT_AVAILABLE".
        This differs from alert/commit DataFrames which raise KeyError for missing columns.
        """
        anomaly_df = pd.DataFrame([{"anomaly_score": 0.5, "reason": "unknown"}])
        result = get_anomaly_summary(anomaly_df)
        assert result["anomaly_status"] == "NOT_AVAILABLE"
        assert result["anomaly_score"] == 0.5


# ---------------------------------------------------------------------------
# Part 1.B – write_decision conditional output branches (lines 241–262)
# ---------------------------------------------------------------------------

class TestWriteDecisionConditionalBranches:
    """
    Test write_decision when non-empty issue summaries are present to exercise
    the conditional print branches around lines 241–262.
    """

    def test_write_decision_prints_commit_high_issues(self, tmp_path, monkeypatch, capsys):
        monkeypatch.chdir(tmp_path)
        result = _sample_decision_result(decision="BLOCK")
        result["commit_high_issues"] = "commit-risk | src/vuln.py | risk score: 0.95"
        write_decision(result)
        captured = capsys.readouterr()
        assert "HIGH commit risk functions:" in captured.out
        assert "src/vuln.py" in captured.out

    def test_write_decision_prints_commit_review_required_issues(self, tmp_path, monkeypatch, capsys):
        monkeypatch.chdir(tmp_path)
        result = _sample_decision_result(decision="REVIEW")
        result["commit_review_required_issues"] = "commit-risk | src/uncertain.py | risk score: 0.6"
        write_decision(result)
        captured = capsys.readouterr()
        assert "REVIEW_REQUIRED functions:" in captured.out
        assert "src/uncertain.py" in captured.out

    def test_write_decision_prints_commit_medium_issues(self, tmp_path, monkeypatch, capsys):
        monkeypatch.chdir(tmp_path)
        result = _sample_decision_result(decision="REVIEW")
        result["commit_medium_issues"] = "commit-risk | src/medium.py | risk score: 0.5"
        write_decision(result)
        captured = capsys.readouterr()
        assert "MEDIUM commit risk functions:" in captured.out
        assert "src/medium.py" in captured.out

    def test_write_decision_prints_alert_high_issues(self, tmp_path, monkeypatch, capsys):
        monkeypatch.chdir(tmp_path)
        result = _sample_decision_result(decision="BLOCK")
        result["alert_high_issues"] = "cppcheck | CWE-123 | src/vuln.c:42 | buffer overflow"
        write_decision(result)
        captured = capsys.readouterr()
        assert "HIGH SAST issues:" in captured.out
        assert "buffer overflow" in captured.out

    def test_write_decision_prints_alert_medium_issues(self, tmp_path, monkeypatch, capsys):
        monkeypatch.chdir(tmp_path)
        result = _sample_decision_result(decision="REVIEW")
        result["alert_medium_issues"] = "clang | CWE-456 | src/warn.c:10 | possible null deref"
        write_decision(result)
        captured = capsys.readouterr()
        assert "MEDIUM SAST issues:" in captured.out
        assert "possible null deref" in captured.out

    def test_write_decision_prints_alert_low_issues(self, tmp_path, monkeypatch, capsys):
        monkeypatch.chdir(tmp_path)
        result = _sample_decision_result(decision="PASS")
        result["alert_low_issues"] = "cppcheck | style-01 | src/style.c:5 | style issue"
        write_decision(result)
        captured = capsys.readouterr()
        assert "LOW SAST issues:" in captured.out
        assert "style issue" in captured.out


# ---------------------------------------------------------------------------
# Part 1.C – main() entry-point behaviour
# ---------------------------------------------------------------------------

class TestMainEntryPoint:
    """
    Test main() without reading or writing real repository reports.
    Use monkeypatch to replace report paths or component functions.
    """

    def test_main_loads_all_four_component_reports(self, tmp_path, monkeypatch):
        """main() calls load_report four times with correct report paths."""
        monkeypatch.chdir(tmp_path)
        load_calls = []

        def mock_load_report(path, name):
            load_calls.append((path, name))
            return pd.DataFrame()

        monkeypatch.setattr(sde_module, "load_report", mock_load_report)
        monkeypatch.setattr(sde_module, "calculate_decision", lambda *a: _sample_decision_result())
        monkeypatch.setattr(sde_module, "write_decision", lambda r: None)

        sde_module.main()

        assert len(load_calls) == 4
        paths = [call[0] for call in load_calls]
        assert "commit_risk_report.csv" in paths[0]
        assert "cppcheck" in paths[1]
        assert "clang" in paths[2]
        assert "anomaly_report.csv" in paths[3]

    def test_main_passes_reports_to_calculate_decision(self, tmp_path, monkeypatch):
        """main() passes the four loaded DataFrames to calculate_decision."""
        monkeypatch.chdir(tmp_path)
        calc_args = []

        def mock_calculate_decision(*args):
            calc_args.extend(args)
            return _sample_decision_result()

        monkeypatch.setattr(sde_module, "load_report", lambda p, n: pd.DataFrame())
        monkeypatch.setattr(sde_module, "calculate_decision", mock_calculate_decision)
        monkeypatch.setattr(sde_module, "write_decision", lambda r: None)

        sde_module.main()

        assert len(calc_args) == 4

    def test_main_calls_write_decision(self, tmp_path, monkeypatch):
        """main() calls write_decision with the result from calculate_decision."""
        monkeypatch.chdir(tmp_path)
        write_calls = []

        def mock_write_decision(result):
            write_calls.append(result)

        monkeypatch.setattr(sde_module, "load_report", lambda p, n: pd.DataFrame())
        monkeypatch.setattr(sde_module, "calculate_decision", lambda *a: _sample_decision_result())
        monkeypatch.setattr(sde_module, "write_decision", mock_write_decision)

        sde_module.main()

        assert len(write_calls) == 1
        assert write_calls[0]["decision"] == "PASS"

    def test_main_block_decision_raises_systemexit_1(self, tmp_path, monkeypatch, capsys):
        """main() raises SystemExit(1) when decision is BLOCK."""
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(sde_module, "load_report", lambda p, n: pd.DataFrame())
        monkeypatch.setattr(sde_module, "calculate_decision",
                            lambda *a: _sample_decision_result(decision="BLOCK"))
        monkeypatch.setattr(sde_module, "write_decision", lambda r: None)

        with pytest.raises(SystemExit) as exc_info:
            sde_module.main()

        assert exc_info.value.code == 1
        captured = capsys.readouterr()
        assert "SECURITY GATE: BLOCK" in captured.out

    def test_main_pass_decision_does_not_raise(self, tmp_path, monkeypatch, capsys):
        """main() returns normally when decision is PASS."""
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(sde_module, "load_report", lambda p, n: pd.DataFrame())
        monkeypatch.setattr(sde_module, "calculate_decision",
                            lambda *a: _sample_decision_result(decision="PASS"))
        monkeypatch.setattr(sde_module, "write_decision", lambda r: None)

        try:
            sde_module.main()
        except SystemExit:
            pytest.fail("main() raised SystemExit unexpectedly for PASS decision")

        captured = capsys.readouterr()
        assert "Pipeline passed security decision" in captured.out

    def test_main_review_decision_does_not_raise(self, tmp_path, monkeypatch, capsys):
        """main() returns normally when decision is REVIEW (current implementation)."""
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(sde_module, "load_report", lambda p, n: pd.DataFrame())
        monkeypatch.setattr(sde_module, "calculate_decision",
                            lambda *a: _sample_decision_result(decision="REVIEW"))
        monkeypatch.setattr(sde_module, "write_decision", lambda r: None)

        try:
            sde_module.main()
        except SystemExit:
            pytest.fail("main() raised SystemExit unexpectedly for REVIEW decision")

        captured = capsys.readouterr()
        assert "manual security review" in captured.out


# ---------------------------------------------------------------------------
# Part 1.D – Missing report fail-open behaviour
# ---------------------------------------------------------------------------

class TestMissingComponentReportsFailOpenPolicy:
    """
    Document the current combined behaviour when expected ML1, Cppcheck and Clang
    report files are missing: load_report returns empty DataFrames, and
    calculate_decision produces PASS when all component DataFrames are empty.

    This is the current production implementation; this test does not change
    that behaviour. It is recorded as a known limitation.
    """

    def test_missing_component_reports_follow_current_empty_report_policy(
        self, tmp_path, monkeypatch
    ):
        """
        When all expected report files are missing, load_report returns empty
        DataFrames for each component, and calculate_decision returns PASS
        (current production behaviour).
        """
        monkeypatch.chdir(tmp_path)

        # Simulate missing files by using paths that do not exist
        commit_df = load_report(str(tmp_path / "missing_commit.csv"), "ML1")
        cppcheck_df = load_report(str(tmp_path / "missing_cppcheck.csv"), "Cppcheck")
        clang_df = load_report(str(tmp_path / "missing_clang.csv"), "Clang")
        anomaly_df = load_report(str(tmp_path / "missing_anomaly.csv"), "ML3")

        assert commit_df.empty
        assert cppcheck_df.empty
        assert clang_df.empty
        assert anomaly_df.empty

        result = calculate_decision(commit_df, cppcheck_df, clang_df, anomaly_df)

        # Current production behaviour: empty reports produce PASS
        assert result["decision"] == "PASS"
        assert "no" in result["reason"].lower()
