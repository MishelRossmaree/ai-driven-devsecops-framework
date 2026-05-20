import os
import time
import pandas as pd
from pathlib import Path


COMMIT_RISK_REPORT = (
    "reports/commit_risk/commit_risk_report.csv"
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
REPORT_OUTPUT_FILE = REPORT_OUTPUT_DIR / "pipeline_metrics.csv"


def safe_read_csv(path):
    if not os.path.exists(path):
        return pd.DataFrame()

    try:
        return pd.read_csv(path)
    except Exception:
        return pd.DataFrame()


def count_priority(df, priority):
    if df.empty or "priority" not in df.columns:
        return 0

    return df["priority"].eq(priority).sum()


def count_risk(df, level):
    if df.empty or "risk_level" not in df.columns:
        return 0

    return df["risk_level"].eq(level).sum()


def main():
    HISTORY_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    commit_df = safe_read_csv(COMMIT_RISK_REPORT)
    cppcheck_df = safe_read_csv(CPPCHECK_REPORT)
    clang_df = safe_read_csv(CLANG_REPORT)

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

    total_files_scanned = len(commit_df)

    if total_files_scanned > 0:
        alerts_per_file = round(
            total_alerts / total_files_scanned,
            2
        )
    else:
        alerts_per_file = 0

    run_data = {
        "timestamp": int(time.time()),

        "total_files_scanned": total_files_scanned,

        "total_alerts": total_alerts,

        "high_alerts": high_alerts,
        "medium_alerts": medium_alerts,
        "low_alerts": low_alerts,

        "high_commit_risk": high_commit_risk,
        "medium_commit_risk": medium_commit_risk,
        "low_commit_risk": low_commit_risk,

        "alerts_per_file": alerts_per_file
    }

    new_row = pd.DataFrame([run_data])

    if HISTORY_OUTPUT_FILE.exists():
        existing_df = pd.read_csv(HISTORY_OUTPUT_FILE)

        if "decision" in existing_df.columns:
            existing_df = existing_df.drop(columns=["decision"])

        updated_df = pd.concat(
            [existing_df, new_row],
            ignore_index=True
        )
    else:
        updated_df = new_row

    updated_df.to_csv(
        HISTORY_OUTPUT_FILE,
        index=False
    )

    updated_df.to_csv(
        REPORT_OUTPUT_FILE,
        index=False
    )

    print("\nPipeline metrics collected successfully")
    print(f"History saved to: {HISTORY_OUTPUT_FILE}")
    print(f"Report copy saved to: {REPORT_OUTPUT_FILE}")
    print(updated_df.tail())


if __name__ == "__main__":
    main()