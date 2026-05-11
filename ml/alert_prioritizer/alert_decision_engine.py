import os
import pandas as pd

CPPCHECK_REPORT = (
    "reports/alert_prioritizer/cppcheck/prioritised-alerts.csv"
)

CLANG_REPORT = (
    "reports/alert_prioritizer/clang/prioritised-alerts.csv"
)

OUTPUT_FILE = (
    "reports/final_decision/security_decision.csv"
)


def load_report(path, tool_name):
    if not os.path.exists(path):
        print(f"{tool_name} report not found: {path}")
        return pd.DataFrame()

    df = pd.read_csv(path)

    if df.empty:
        print(f"{tool_name} report is empty.")
        return pd.DataFrame()

    return df


def build_issue_summary(df, priority, max_items=5):
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

        summary = (
            f"{tool} | {alert_id} | {location} | {message}"
        )

        summaries.append(summary)

    return " ; ".join(summaries)


def calculate_decision(cppcheck_df, clang_df):
    combined = pd.concat(
        [cppcheck_df, clang_df],
        ignore_index=True
    )

    if combined.empty:
        return {
            "decision": "PASS",
            "reason": "No alerts detected",
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "high_issues": "",
            "medium_issues": "",
            "low_issues": ""
        }

    high_count = combined["priority"].eq("HIGH").sum()
    medium_count = combined["priority"].eq("MEDIUM").sum()
    low_count = combined["priority"].eq("LOW").sum()

    if high_count > 0:
        decision = "BLOCK"
        reason = "High severity alerts detected"

    elif medium_count > 0:
        decision = "REVIEW"
        reason = "Medium severity alerts detected"

    else:
        decision = "PASS"
        reason = "Only low severity alerts detected"

    return {
        "decision": decision,
        "reason": reason,
        "high_count": high_count,
        "medium_count": medium_count,
        "low_count": low_count,
        "high_issues": build_issue_summary(combined, "HIGH"),
        "medium_issues": build_issue_summary(combined, "MEDIUM"),
        "low_issues": build_issue_summary(combined, "LOW")
    }


def write_decision(result):
    os.makedirs(
        "reports/final_decision",
        exist_ok=True
    )

    df = pd.DataFrame([result])

    df.to_csv(
        OUTPUT_FILE,
        index=False
    )

    print("\n===== FINAL SECURITY DECISION =====")
    print(f"Decision: {result['decision']}")
    print(f"Reason: {result['reason']}")
    print(f"HIGH alerts: {result['high_count']}")
    print(f"MEDIUM alerts: {result['medium_count']}")
    print(f"LOW alerts: {result['low_count']}")

    if result["high_issues"]:
        print("\nHIGH issues:")
        print(result["high_issues"])

    if result["medium_issues"]:
        print("\nMEDIUM issues:")
        print(result["medium_issues"])

    if result["low_issues"]:
        print("\nLOW issues:")
        print(result["low_issues"])

    print(f"\nDecision report saved: {OUTPUT_FILE}")


def main():
    cppcheck_df = load_report(
        CPPCHECK_REPORT,
        "Cppcheck"
    )

    clang_df = load_report(
        CLANG_REPORT,
        "Clang"
    )

    result = calculate_decision(
        cppcheck_df,
        clang_df
    )

    write_decision(result)

    if result["decision"] == "BLOCK":
        print("\nPipeline blocked due to HIGH severity alerts.")
        raise SystemExit(1)

    if result["decision"] == "REVIEW":
        print("\nPipeline requires manual security review.")
        return

    print("\nPipeline passed security decision.")


if __name__ == "__main__":
    main()