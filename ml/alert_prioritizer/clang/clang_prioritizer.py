import csv
import os
import re
import html
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


def clean_text(value):
    if not value:
        return ""

    value = html.unescape(value)
    value = re.sub(r"<[^>]+>", "", value)
    value = re.sub(r"\s+", " ", value)

    return value.strip()


def extract_with_patterns(content, patterns):
    for pattern in patterns:
        match = re.search(
            pattern,
            content,
            re.IGNORECASE | re.DOTALL
        )

        if match:
            return clean_text(match.group(1))

    return ""


def determine_priority(message):
    lower_message = message.lower()

    high_keywords = [
        "null",
        "dereference",
        "use after free",
        "double free",
        "overflow",
        "buffer",
        "uninitialized",
        "dead store"
    ]

    medium_keywords = [
        "memory",
        "leak",
        "warning",
        "value stored",
        "never read"
    ]

    if any(keyword in lower_message for keyword in high_keywords):
        return "HIGH"

    if any(keyword in lower_message for keyword in medium_keywords):
        return "MEDIUM"

    return "LOW"


def parse_clang_reports():
    alerts = []

    html_reports = extract_html_reports()

    print(f"Found {len(html_reports)} Clang reports.")

    for report_file in html_reports:
        try:
            with open(report_file, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            message = extract_with_patterns(
                content,
                [
                    r"<!--\s*BUGDESC\s*(.*?)\s*-->",
                    r"<h3[^>]*>(.*?)</h3>",
                    r"<title>(.*?)</title>"
                ]
            )

            file_name = extract_with_patterns(
                content,
                [
                    r"<!--\s*BUGFILE\s*(.*?)\s*-->",
                    r"File:\s*</td>\s*<td[^>]*>(.*?)</td>",
                    r"File:\s*(.*?)<"
                ]
            )

            line_number = extract_with_patterns(
                content,
                [
                    r"<!--\s*BUGLINE\s*(\d+)\s*-->",
                    r"Line:\s*</td>\s*<td[^>]*>(\d+)</td>",
                    r"Line:\s*(\d+)"
                ]
            )

            if not message:
                message = "Unknown Clang issue"

            if not file_name:
                file_name = report_file

            priority = determine_priority(message)

            alerts.append({
                "tool": "clang",
                "file": file_name,
                "line": line_number,
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
        location = (
            f"{alert['file']}:{alert['line']}"
            if alert["line"]
            else alert["file"]
        )

        print(
            f"{alert['priority']} | "
            f"{alert['tool']} | "
            f"{location} | "
            f"{alert['message']}"
        )


if __name__ == "__main__":
    main()