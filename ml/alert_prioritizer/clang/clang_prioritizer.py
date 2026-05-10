import csv
import os
import re
import pandas as pd

CLANG_REPORT_DIR = "reports/clang-report"

OUTPUT_FILE = (
    "reports/alert_prioritizer/clang/prioritised-alerts.csv"
)

LABEL_MAP = {
    "HIGH": 2,
    "MEDIUM": 1,
    "LOW": 0
}


def extract_html_reports():
    html_files = []

    for root, _, files in os.walk(CLANG_REPORT_DIR):
        for file in files:
            if file.endswith(".html") and file.startswith("report-"):
                html_files.append(os.path.join(root, file))

    return html_files


def parse_clang_reports():
    alerts = []

    html_reports = extract_html_reports()

    print(f"Found {len(html_reports)} Clang reports.")

    for report_file in html_reports:
        try:
            with open(report_file, "r", encoding="utf-8") as f:
                content = f.read()

            title_match = re.search(
                r"<title>(.*?)</title>",
                content,
                re.IGNORECASE | re.DOTALL
            )

            message = (
                title_match.group(1).strip()
                if title_match
                else "Unknown Clang issue"
            )

            lower_message = message.lower()

            priority = "LOW"

            if any(keyword in lower_message for keyword in [
                "null",
                "dereference",
                "use after free",
                "double free",
                "overflow",
                "buffer"
            ]):
                priority = "HIGH"

            elif any(keyword in lower_message for keyword in [
                "memory",
                "leak",
                "warning"
            ]):
                priority = "MEDIUM"

            alerts.append({
                "tool": "clang",
                "file": report_file,
                "line": "",
                "alert_id": "clang-static-analyzer",
                "cwe": "",
                "severity": "warning",
                "message": message,
                "priority": priority,
                "label": LABEL_MAP[priority]
            })

        except Exception as e:
            print(f"Error parsing {report_file}: {e}")

    return pd.DataFrame(alerts)


def write_prioritised_alerts(df):
    os.makedirs(
        "reports/alert_prioritizer/clang",
        exist_ok=True
    )

    output_columns = [
        "priority",
        "tool",
        "file",
        "line",
        "alert_id",
        "cwe",
        "severity",
        "message"
    ]

    if df.empty:
        with open(
            OUTPUT_FILE,
            "w",
            newline="",
            encoding="utf-8"
        ) as csvfile:
            writer = csv.writer(csvfile)

            writer.writerow(output_columns)

        print("No Clang alerts found.")
        return

    priority_order = {
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1
    }

    df["priority_rank"] = df["priority"].map(priority_order)

    df = df.sort_values(
        by="priority_rank",
        ascending=False
    )

    df[output_columns].to_csv(
        OUTPUT_FILE,
        index=False
    )

    print(
        f"Clang prioritised alerts generated: "
        f"{OUTPUT_FILE}"
    )


def main():
    df = parse_clang_reports()

    write_prioritised_alerts(df)

    print("===== Clang Prioritised Alerts =====")

    if df.empty:
        print("No Clang alerts detected.")
        return

    for _, alert in df.iterrows():
        print(
            f"{alert['priority']} | "
            f"{alert['tool']} | "
            f"{alert['message']}"
        )


if __name__ == "__main__":
    main()