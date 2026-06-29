import os
import pandas as pd


COMMIT_RISK_REPORT = (
    "reports/commit_risk/commit_risk_report.csv"
)

CPPCHECK_REPORT = (
    "reports/alert_prioritizer/cppcheck/prioritised-alerts.csv"
)

CLANG_REPORT = (
    "reports/alert_prioritizer/clang/prioritised-alerts.csv"
)

ANOMALY_REPORT = (
    "reports/anomaly_detection/anomaly_report.csv"
)

OUTPUT_FILE = (
    "reports/final_decision/security_decision.csv"
)


def load_report(path, report_name):
    if not os.path.exists(path):
        print(f"{report_name} report not found: {path}")
        return pd.DataFrame()

    df = pd.read_csv(path)

    if df.empty:
        print(f"{report_name} report is empty.")
        return pd.DataFrame()

    return df


def build_alert_summary(df, priority, max_items=5):
    if df.empty:
        return ""

    selected = df[df["priority"] == priority].head(max_items)
    summaries = []

    for _, row in selected.iterrows():
        tool = row.get("tool", "unknown")
        file = row.get("file", "")
        line = row.get("line", "")
        alert_id = row.get("alert_id", "")
        message = row.get("message", "")

        location = file

        if pd.notna(line) and str(line).strip() != "":
            location = f"{file}:{line}"

        summaries.append(f"{tool} | {alert_id} | {location} | {message}")

    return " ; ".join(summaries)


def build_commit_risk_summary(df, risk_level, max_items=5):
    if df.empty:
        return ""

    selected = df[df["risk_level"] == risk_level].head(max_items)
    summaries = []

    for _, row in selected.iterrows():
        file_path = row.get("file_path", "")
        risk_score = row.get("risk_score", "")

        summaries.append(
            f"commit-risk | {file_path} | risk score: {risk_score}"
        )

    return " ; ".join(summaries)


def get_anomaly_summary(anomaly_df):
    if anomaly_df.empty:
        return {
            "anomaly_status": "NOT_AVAILABLE",
            "anomaly_score": "",
            "anomaly_reason": "ML3 anomaly report not available"
        }

    row = anomaly_df.iloc[0]

    return {
        "anomaly_status": row.get("anomaly_status", "NOT_AVAILABLE"),
        "anomaly_score": row.get("anomaly_score", ""),
        "anomaly_reason": (
            f"ML3 pipeline anomaly status: {row.get('anomaly_status', 'NOT_AVAILABLE')}, "
            f"score: {row.get('anomaly_score', '')}"
        )
    }


def calculate_decision(commit_df, cppcheck_df, clang_df, anomaly_df):
    alerts_combined = pd.concat(
        [cppcheck_df, clang_df],
        ignore_index=True
    )

    if alerts_combined.empty:
        alert_high_count = 0
        alert_medium_count = 0
        alert_low_count = 0
    else:
        alert_high_count = alerts_combined["priority"].eq("HIGH").sum()
        alert_medium_count = alerts_combined["priority"].eq("MEDIUM").sum()
        alert_low_count = alerts_combined["priority"].eq("LOW").sum()

    if commit_df.empty:
        commit_high_count = 0
        commit_review_required_count = 0
        commit_medium_count = 0
        commit_low_count = 0
    else:
        commit_high_count = commit_df["risk_level"].eq("HIGH").sum()
        commit_review_required_count = commit_df["risk_level"].eq("REVIEW_REQUIRED").sum()
        commit_medium_count = commit_df["risk_level"].eq("MEDIUM").sum()
        commit_low_count = commit_df["risk_level"].eq("LOW").sum()

    anomaly_summary = get_anomaly_summary(anomaly_df)
    anomaly_status = anomaly_summary["anomaly_status"]

    if commit_high_count > 0 or alert_high_count > 0:
        decision = "BLOCK"
        reason = "High commit risk or high severity security alerts detected"

    elif commit_review_required_count > 0:
        decision = "REVIEW"
        reason = "Low-confidence ML1 predictions require manual review"

    elif anomaly_status == "ANOMALOUS":
        decision = "REVIEW"
        reason = "Anomalous CI/CD pipeline behaviour detected by ML3"

    elif commit_medium_count > 0 or alert_medium_count > 0:
        decision = "REVIEW"
        reason = "Medium commit risk or medium severity security alerts detected"

    else:
        decision = "PASS"

        if commit_low_count > 0 or alert_low_count > 0:
            reason = "Only low risk findings detected"
        else:
            reason = "No commit risk, security alerts, or anomaly detected"

    return {
        "decision": decision,
        "reason": reason,

        "commit_high_count": commit_high_count,
        "commit_review_required_count": commit_review_required_count,
        "commit_medium_count": commit_medium_count,
        "commit_low_count": commit_low_count,

        "alert_high_count": alert_high_count,
        "alert_medium_count": alert_medium_count,
        "alert_low_count": alert_low_count,

        "anomaly_status": anomaly_summary["anomaly_status"],
        "anomaly_score": anomaly_summary["anomaly_score"],
        "anomaly_reason": anomaly_summary["anomaly_reason"],

        "commit_high_issues": build_commit_risk_summary(commit_df, "HIGH"),
        "commit_review_required_issues": build_commit_risk_summary(commit_df, "REVIEW_REQUIRED"),
        "commit_medium_issues": build_commit_risk_summary(commit_df, "MEDIUM"),
        "commit_low_issues": build_commit_risk_summary(commit_df, "LOW"),

        "alert_high_issues": build_alert_summary(alerts_combined, "HIGH"),
        "alert_medium_issues": build_alert_summary(alerts_combined, "MEDIUM"),
        "alert_low_issues": build_alert_summary(alerts_combined, "LOW")
    }


def write_decision(result):
    os.makedirs(
        "reports/final_decision",
        exist_ok=True
    )

    df = pd.DataFrame([result])
    df.to_csv(OUTPUT_FILE, index=False)

    print("\n===== FINAL SECURITY DECISION =====")
    print(f"Decision: {result['decision']}")
    print(f"Reason: {result['reason']}")

    print("\n===== ML 1 COMMIT RISK SUMMARY =====")
    print(f"HIGH commit risk functions: {result['commit_high_count']}")
    print(f"REVIEW_REQUIRED functions: {result['commit_review_required_count']}")
    print(f"MEDIUM commit risk functions: {result['commit_medium_count']}")
    print(f"LOW commit risk functions: {result['commit_low_count']}")

    print("\n===== ML 2 SAST ALERT SUMMARY =====")
    print(f"HIGH alerts: {result['alert_high_count']}")
    print(f"MEDIUM alerts: {result['alert_medium_count']}")
    print(f"LOW alerts: {result['alert_low_count']}")

    print("\n===== ML 3 PIPELINE ANOMALY SUMMARY =====")
    print(f"Anomaly status: {result['anomaly_status']}")
    print(f"Anomaly score: {result['anomaly_score']}")

    if result["commit_high_issues"]:
        print("\nHIGH commit risk functions:")
        print(result["commit_high_issues"])

    if result["commit_review_required_issues"]:
        print("\nREVIEW_REQUIRED functions:")
        print(result["commit_review_required_issues"])

    if result["commit_medium_issues"]:
        print("\nMEDIUM commit risk functions:")
        print(result["commit_medium_issues"])

    if result["alert_high_issues"]:
        print("\nHIGH SAST issues:")
        print(result["alert_high_issues"])

    if result["alert_medium_issues"]:
        print("\nMEDIUM SAST issues:")
        print(result["alert_medium_issues"])

    if result["alert_low_issues"]:
        print("\nLOW SAST issues:")
        print(result["alert_low_issues"])

    print(f"\nDecision report saved: {OUTPUT_FILE}")


def main():
    commit_df = load_report(COMMIT_RISK_REPORT, "Commit risk")
    cppcheck_df = load_report(CPPCHECK_REPORT, "Cppcheck")
    clang_df = load_report(CLANG_REPORT, "Clang")
    anomaly_df = load_report(ANOMALY_REPORT, "ML3 anomaly")

    result = calculate_decision(
        commit_df,
        cppcheck_df,
        clang_df,
        anomaly_df
    )

    write_decision(result)

    if result["decision"] == "BLOCK":
        print("\n==============================")
        print("SECURITY GATE: BLOCK")
        print("==============================")
        print("This commit is blocked from merging into the protected main branch.")
        print(f"Reason: {result['reason']}")
        print("Action required: Fix the security issue or request manual review.")
        raise SystemExit(1)

    if result["decision"] == "REVIEW":
        print("\nPipeline requires manual security review.")
        return

    print("\nPipeline passed security decision.")


if __name__ == "__main__":
    main()