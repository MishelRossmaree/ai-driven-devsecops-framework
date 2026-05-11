import csv
import os
import re
import html
import pandas as pd
import joblib

CLANG_REPORT_DIR = "reports/clang-report"

OUTPUT_FILE = (
    "reports/alert_prioritizer/clang/prioritised-alerts.csv"
)

ACTION_PATH = os.environ.get("GITHUB_ACTION_PATH", ".")
MODEL_PATH = os.path.join(
    ACTION_PATH, "models", "alert_prioritizer", "clang", "clang_priority_model.pkl"
)

LABEL_MAP = {
    0: "LOW",
    1: "MEDIUM",
    2: "HIGH"
}

PRIORITY_MAP = {
    "LOW": 0,
    "MEDIUM": 1,
    "HIGH": 2
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


def severity_to_score(severity):
    severity = str(severity).lower()
    mapping = {
        "critical": 4,
        "error": 3,
        "warning": 2,
        "note": 1,
        "information": 1,
    }
    return mapping.get(severity, 0)


def has_value(value):
    if value is None:
        return 0
    value = str(value).strip()
    if value == "" or value.lower() in ["nan", "none", "null"]:
        return 0
    return 1


def keyword_feature(text, keywords):
    text = str(text).lower()
    return int(any(keyword in text for keyword in keywords))


def build_features(message, alert_id, severity, cwe):
    return {
        "severity_score": severity_to_score(severity),
        "has_cwe": has_value(cwe),
        "is_null_pointer": keyword_feature(
            message, ["null pointer", "nullpointer", "null"]
        ),
        "is_buffer_issue": keyword_feature(
            message, ["buffer", "overflow", "overrun", "out of bounds"]
        ),
        "is_memory_issue": keyword_feature(
            message, ["memory", "memleak", "leak", "free", "dereference"]
        ),
        "is_obsolete_function": keyword_feature(
            message, ["gets", "strcpy", "strcat", "sprintf"]
        ),
        "is_clang": 1,
        "alert_id": str(alert_id),
        "severity": str(severity),
        "cwe": str(cwe),
        "message": str(message),
    }


def load_model():
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(
            f"Trained model not found at {MODEL_PATH}. "
            "Run train_clang_model.py first."
        )
    return joblib.load(MODEL_PATH)


def parse_clang_reports(model):
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

            features = build_features(
                message=message,
                alert_id="clang-static-analyzer",
                severity="warning",
                cwe=""
            )

            df_features = pd.DataFrame([features])
            label = model.predict(df_features)[0]
            priority = LABEL_MAP[label]

            alerts.append({
                "tool": "clang",
                "file": file_name,
                "line": line_number,
                "alert_id": "clang-static-analyzer",
                "cwe": "",
                "severity": "warning",
                "message": message,
                "priority": priority,
                "label": label
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
    model = load_model()

    df = parse_clang_reports(model)

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