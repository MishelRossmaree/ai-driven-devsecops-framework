import json
import os
from datetime import datetime, timezone
from pathlib import Path

import joblib
import pandas as pd


HISTORY_DIR = Path(".devsecops/anomaly_detection")
HISTORY_FILE = HISTORY_DIR / "pipeline_metrics.csv"
MODEL_PATH = Path(".devsecops/anomaly_detection/models/anomaly_model.pkl")
SCALER_PATH = Path(".devsecops/anomaly_detection/models/anomaly_scaler.pkl")
METADATA_PATH = Path(".devsecops/anomaly_detection/models/anomaly_model_metadata.json")

REPORT_DIR = Path("reports/anomaly_detection")
CURRENT_METRICS_FILE = REPORT_DIR / "current_pipeline_metrics.csv"
REPORT_FILE = REPORT_DIR / "anomaly_report.csv"

DEFAULT_MIN_ROWS = 30

DEFAULT_FEATURE_COLUMNS = [
    "total_files_scanned",
    "total_alerts",
    "high_alerts",
    "medium_alerts",
    "low_alerts",
    "high_commit_risk",
    "medium_commit_risk",
    "low_commit_risk",
    "alerts_per_file"
]

OPERATIONAL_COLUMNS = [
    "ml3_scoring_blocked",
    "ml3_scoring_block_reason",
    "commit_risk_status",
    "commit_summary_status",
    "cppcheck_status",
    "clang_status"
]


def to_bool(value):
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "y"}


def utc_now_iso():
    return datetime.now(timezone.utc).isoformat()


def get_history_row_count():
    if not HISTORY_FILE.exists():
        return 0
    try:
        history_df = pd.read_csv(HISTORY_FILE)
        return len(history_df)
    except Exception:
        return 0


def get_run_identifier(current_row):
    candidate = str(current_row.get("ml3_run_id", "")).strip()
    if candidate:
        return candidate

    github_run_id = str(current_row.get("github_run_id", "")).strip() or str(os.environ.get("GITHUB_RUN_ID", "")).strip()
    commit_sha = str(current_row.get("commit_sha", "")).strip() or str(os.environ.get("GITHUB_SHA", "")).strip()
    timestamp_value = str(current_row.get("timestamp", "")).strip()

    if github_run_id:
        return f"gh_run:{github_run_id}"
    if commit_sha and timestamp_value:
        return f"sha:{commit_sha}:{timestamp_value}"
    if commit_sha:
        return f"sha:{commit_sha}"
    if timestamp_value:
        return f"ts:{timestamp_value}"
    return ""


def append_current_row_once(current_row, outcome, reason, failure_reason):
    HISTORY_DIR.mkdir(parents=True, exist_ok=True)

    row_to_append = dict(current_row)
    row_to_append["ml3_outcome"] = outcome
    row_to_append["ml3_reason"] = reason
    row_to_append["ml3_failure_reason"] = failure_reason

    run_id = get_run_identifier(row_to_append)
    if run_id:
        row_to_append["ml3_run_id"] = run_id

    new_row_df = pd.DataFrame([row_to_append])

    if not HISTORY_FILE.exists():
        new_row_df.to_csv(HISTORY_FILE, index=False)
        return True

    try:
        history_df = pd.read_csv(HISTORY_FILE)
    except Exception:
        # If history is unreadable, preserve existing artifact and skip append.
        return False

    duplicate_found = False

    if run_id and "ml3_run_id" in history_df.columns:
        duplicate_found = history_df["ml3_run_id"].astype(str).eq(run_id).any()
    elif run_id and "github_run_id" in history_df.columns:
        github_run_id = str(row_to_append.get("github_run_id", "")).strip()
        if github_run_id:
            duplicate_found = history_df["github_run_id"].astype(str).eq(github_run_id).any()

    if duplicate_found:
        return False

    updated_df = pd.concat([history_df, new_row_df], ignore_index=True)
    updated_df.to_csv(HISTORY_FILE, index=False)
    return True


def write_report(base_row):
    report_row = dict(base_row)
    pd.DataFrame([report_row]).to_csv(REPORT_FILE, index=False)


def build_base_report(current_row, history_rows_before_append):
    report = {
        "timestamp": utc_now_iso(),
        "anomaly_status": "FAILED",
        "is_anomaly": "",
        "anomaly_score": "",
        "selected_model": "",
        "reason": "",
        "failure_reason": "",
        "ml3_scoring_blocked": False,
        "ml3_scoring_block_reason": "",
        "history_rows_before_append": history_rows_before_append,
        "current_run_appended": False
    }

    for col in OPERATIONAL_COLUMNS:
        if col in current_row:
            report[col] = current_row.get(col)

    return report


def load_current_metrics():
    if not CURRENT_METRICS_FILE.exists():
        return None, "CURRENT_METRICS_FILE_MISSING"

    try:
        current_df = pd.read_csv(CURRENT_METRICS_FILE)
    except Exception as exc:
        return None, f"CURRENT_METRICS_FILE_MALFORMED: {exc}"

    if current_df.empty:
        return None, "CURRENT_METRICS_FILE_EMPTY"

    if len(current_df) != 1:
        return None, f"CURRENT_METRICS_ROW_COUNT_INVALID:{len(current_df)}"

    return current_df, ""


def get_min_rows():
    value = str(os.environ.get("ML3_MIN_ROWS", str(DEFAULT_MIN_ROWS))).strip()
    try:
        parsed = int(value)
        if parsed <= 0:
            return DEFAULT_MIN_ROWS
        return parsed
    except Exception:
        return DEFAULT_MIN_ROWS


def finalise_with_optional_append(current_row, report_row, append_if_possible):
    write_report(report_row)

    appended = False
    if append_if_possible and current_row is not None:
        appended = append_current_row_once(
            current_row=current_row,
            outcome=report_row.get("anomaly_status", ""),
            reason=str(report_row.get("reason", "")),
            failure_reason=str(report_row.get("failure_reason", ""))
        )

    report_row["current_run_appended"] = bool(appended)
    write_report(report_row)
    return report_row


def main():
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    HISTORY_DIR.mkdir(parents=True, exist_ok=True)

    history_rows_before_append = get_history_row_count()
    current_df, load_error = load_current_metrics()

    if current_df is None:
        failure_report = build_base_report({}, history_rows_before_append)
        failure_report["anomaly_status"] = "FAILED"
        failure_report["failure_reason"] = load_error
        failure_report["reason"] = "ML3 current metrics unavailable or invalid"
        finalise_with_optional_append(None, failure_report, append_if_possible=False)
        print(f"ML3 anomaly detection failed gracefully: {load_error}")
        return

    current_row = current_df.iloc[0].to_dict()
    run_id = get_run_identifier(current_row)
    if run_id:
        current_row["ml3_run_id"] = run_id

    base_report = build_base_report(current_row, history_rows_before_append)

    scoring_blocked = to_bool(current_row.get("ml3_scoring_blocked", False))
    scoring_block_reason = str(current_row.get("ml3_scoring_block_reason", "")).strip()
    base_report["ml3_scoring_blocked"] = scoring_blocked
    base_report["ml3_scoring_block_reason"] = scoring_block_reason

    if scoring_blocked:
        base_report["anomaly_status"] = "NOT_AVAILABLE"
        base_report["reason"] = scoring_block_reason or "ML3_SCORING_BLOCKED"
        finalise_with_optional_append(current_row, base_report, append_if_possible=True)
        print("ML3 scoring blocked by upstream status. Report generated and history updated.")
        return

    model_files_available = MODEL_PATH.exists() and SCALER_PATH.exists() and METADATA_PATH.exists()

    if not model_files_available:
        min_rows = get_min_rows()
        reason = "MODEL_NOT_TRAINED"
        if history_rows_before_append < min_rows:
            reason = "INSUFFICIENT_HISTORY"

        base_report["anomaly_status"] = "NOT_AVAILABLE"
        base_report["reason"] = reason
        finalise_with_optional_append(current_row, base_report, append_if_possible=True)
        print(f"ML3 model unavailable ({reason}). Report generated and history updated.")
        return

    try:
        with open(METADATA_PATH, "r", encoding="utf-8") as metadata_file:
            metadata = json.load(metadata_file)
    except Exception as exc:
        base_report["anomaly_status"] = "FAILED"
        base_report["failure_reason"] = f"METADATA_LOAD_FAILED: {exc}"
        base_report["reason"] = "ML3 model metadata is unreadable"
        finalise_with_optional_append(current_row, base_report, append_if_possible=False)
        return

    feature_columns = metadata.get("feature_columns", DEFAULT_FEATURE_COLUMNS)
    missing_feature_columns = [column for column in feature_columns if column not in current_df.columns]
    if missing_feature_columns:
        base_report["anomaly_status"] = "FAILED"
        base_report["failure_reason"] = "CURRENT_METRICS_SCHEMA_INCOMPATIBLE: missing feature columns " + ", ".join(missing_feature_columns)
        base_report["reason"] = "Current metrics schema is incompatible with trained model"
        finalise_with_optional_append(current_row, base_report, append_if_possible=False)
        return

    feature_df = current_df[feature_columns].copy()
    for column in feature_columns:
        numeric_column = pd.to_numeric(feature_df[column], errors="coerce")
        if numeric_column.isna().any():
            base_report["anomaly_status"] = "FAILED"
            base_report["failure_reason"] = f"CURRENT_METRICS_NON_NUMERIC_FEATURE:{column}"
            base_report["reason"] = "Current metrics contain non-numeric feature values"
            finalise_with_optional_append(current_row, base_report, append_if_possible=False)
            return
        feature_df[column] = numeric_column

    try:
        model = joblib.load(MODEL_PATH)
        scaler = joblib.load(SCALER_PATH)
    except Exception as exc:
        base_report["anomaly_status"] = "FAILED"
        base_report["failure_reason"] = f"MODEL_OR_SCALER_LOAD_FAILED: {exc}"
        base_report["reason"] = "ML3 model artifact load failed"
        finalise_with_optional_append(current_row, base_report, append_if_possible=False)
        return

    try:
        scaled_features = scaler.transform(feature_df)
        prediction = model.predict(scaled_features)[0]
        score = ""
        if hasattr(model, "decision_function"):
            score = round(float(model.decision_function(scaled_features)[0]), 6)
    except Exception as exc:
        base_report["anomaly_status"] = "FAILED"
        base_report["failure_reason"] = f"INFERENCE_FAILED: {exc}"
        base_report["reason"] = "ML3 inference failed"
        finalise_with_optional_append(current_row, base_report, append_if_possible=False)
        return

    anomaly_status = "ANOMALOUS" if int(prediction) == -1 else "NORMAL"
    base_report["anomaly_status"] = anomaly_status
    base_report["is_anomaly"] = bool(anomaly_status == "ANOMALOUS")
    base_report["anomaly_score"] = score
    base_report["selected_model"] = str(metadata.get("selected_model", ""))
    base_report["reason"] = "Scored using trained ML3 anomaly model"

    for column in feature_columns:
        base_report[column] = float(feature_df.iloc[0][column])

    finalise_with_optional_append(current_row, base_report, append_if_possible=True)

    print("\nML3 Pipeline Anomaly Detection Completed")
    print(f"Status: {anomaly_status}")
    print(f"Run id: {run_id or 'N/A'}")
    print(f"Report saved to: {REPORT_FILE}")


if __name__ == "__main__":
    main()