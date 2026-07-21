import os
import time
import pandas as pd
from pathlib import Path


COMMIT_RISK_REPORT = (
    "reports/commit_risk/commit_risk_report.csv"
)

COMMIT_RISK_SUMMARY_REPORT = (
    "reports/commit_risk/commit_risk_summary.csv"
)

CPPCHECK_REPORT = (
    "reports/alert_prioritizer/cppcheck/prioritised-alerts.csv"
)

CLANG_REPORT = (
    "reports/alert_prioritizer/clang/prioritised-alerts.csv"
)

HISTORY_OUTPUT_DIR = Path(".devsecops/anomaly_detection")
HISTORY_OUTPUT_FILE = HISTORY_OUTPUT_DIR / "pipeline_metrics.csv"

REPORT_OUTPUT_DIR = Path("reports/anomaly_detection")
CURRENT_REPORT_OUTPUT_FILE = REPORT_OUTPUT_DIR / "current_pipeline_metrics.csv"

STATUS_OK = "OK"
STATUS_MISSING = "MISSING"
STATUS_MALFORMED = "MALFORMED"
STATUS_SCHEMA_MISMATCH = "SCHEMA_MISMATCH"
STATUS_NOT_APPLICABLE = "NOT_APPLICABLE"

REQUIRED_COMMIT_COLUMNS = ["risk_level"]
REQUIRED_COMMIT_SUMMARY_COLUMNS = ["total_changed_files"]
REQUIRED_ALERT_COLUMNS = ["priority"]


def read_csv_with_status(path, required_columns):
    if not os.path.exists(path):
        return pd.DataFrame(), STATUS_MISSING

    try:
        df = pd.read_csv(path)
    except Exception:
        return pd.DataFrame(), STATUS_MALFORMED

    missing_columns = [col for col in required_columns if col not in df.columns]

    if missing_columns:
        return df, STATUS_SCHEMA_MISMATCH

    return df, STATUS_OK


def count_priority(df, priority):
    if df.empty or "priority" not in df.columns:
        return 0

    return df["priority"].eq(priority).sum()


def count_risk(df, level):
    if df.empty or "risk_level" not in df.columns:
        return 0

    return df["risk_level"].eq(level).sum()


def build_run_identifiers(timestamp_value):
    github_run_id = str(os.environ.get("GITHUB_RUN_ID", "")).strip()
    commit_sha = str(os.environ.get("GITHUB_SHA", "")).strip()

    if github_run_id:
        ml3_run_id = f"gh_run:{github_run_id}"
    elif commit_sha:
        ml3_run_id = f"sha:{commit_sha}:{timestamp_value}"
    else:
        ml3_run_id = f"ts:{timestamp_value}"

    return {
        "ml3_run_id": ml3_run_id,
        "github_run_id": github_run_id,
        "commit_sha": commit_sha
    }


def main():
    HISTORY_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    commit_df, commit_status = read_csv_with_status(
        COMMIT_RISK_REPORT,
        REQUIRED_COMMIT_COLUMNS
    )
    commit_summary_df, commit_summary_status = read_csv_with_status(
        COMMIT_RISK_SUMMARY_REPORT,
        REQUIRED_COMMIT_SUMMARY_COLUMNS
    )
    cppcheck_df, cppcheck_status = read_csv_with_status(
        CPPCHECK_REPORT,
        REQUIRED_ALERT_COLUMNS
    )
    clang_df, clang_status = read_csv_with_status(
        CLANG_REPORT,
        REQUIRED_ALERT_COLUMNS
    )

    combined_alerts = pd.concat(
        [cppcheck_df, clang_df],
        ignore_index=True
    )

    high_alerts = count_priority(combined_alerts, "HIGH")
    medium_alerts = count_priority(combined_alerts, "MEDIUM")
    low_alerts = count_priority(combined_alerts, "LOW")

    total_alerts = (
        high_alerts +
        medium_alerts +
        low_alerts
    )

    high_commit_risk = count_risk(commit_df, "HIGH")
    medium_commit_risk = count_risk(commit_df, "MEDIUM")
    low_commit_risk = count_risk(commit_df, "LOW")

    if (
        not commit_summary_df.empty and
        "total_changed_files" in commit_summary_df.columns
    ):
        total_files_scanned = int(commit_summary_df.iloc[0]["total_changed_files"])
    else:
        total_files_scanned = len(commit_df)

    if total_files_scanned > 0:
        alerts_per_file = round(
            total_alerts / total_files_scanned,
            2
        )
    else:
        alerts_per_file = 0

    upstream_statuses = {
        "commit_risk_status": commit_status,
        "commit_summary_status": commit_summary_status,
        "cppcheck_status": cppcheck_status,
        "clang_status": clang_status
    }

    blocking_upstream_statuses = {
        name: status
        for name, status in upstream_statuses.items()
        if status in {STATUS_MISSING, STATUS_MALFORMED, STATUS_SCHEMA_MISMATCH}
    }

    if blocking_upstream_statuses:
        scoring_blocked = True
        scoring_block_reason = (
            "ML3 scoring blocked due to missing, malformed, or schema-incompatible upstream reports: "
            + ", ".join(
                f"{name}={status}"
                for name, status in sorted(blocking_upstream_statuses.items())
            )
        )
    else:
        scoring_blocked = False
        scoring_block_reason = ""

    timestamp_value = int(time.time())
    run_identifiers = build_run_identifiers(timestamp_value)

    run_data = {
        "timestamp": timestamp_value,

        "ml3_run_id": run_identifiers["ml3_run_id"],
        "github_run_id": run_identifiers["github_run_id"],
        "commit_sha": run_identifiers["commit_sha"],

        "total_files_scanned": total_files_scanned,

        "total_alerts": total_alerts,

        "high_alerts": high_alerts,
        "medium_alerts": medium_alerts,
        "low_alerts": low_alerts,

        "high_commit_risk": high_commit_risk,
        "medium_commit_risk": medium_commit_risk,
        "low_commit_risk": low_commit_risk,

        "alerts_per_file": alerts_per_file,

        "commit_risk_status": commit_status,
        "commit_summary_status": commit_summary_status,
        "cppcheck_status": cppcheck_status,
        "clang_status": clang_status,

        "ml3_scoring_blocked": scoring_blocked,
        "ml3_scoring_block_reason": scoring_block_reason
    }

    new_row = pd.DataFrame([run_data])

    new_row.to_csv(
        CURRENT_REPORT_OUTPUT_FILE,
        index=False
    )

    print("\nPipeline metrics collected successfully")
    print("Current metrics row has not been appended to history yet.")
    print(f"Current metrics saved to: {CURRENT_REPORT_OUTPUT_FILE}")
    print(new_row.tail())


if __name__ == "__main__":
    main()