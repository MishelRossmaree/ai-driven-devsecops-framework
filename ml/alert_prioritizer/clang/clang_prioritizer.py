import csv
import os
import re
import sys
import html
import pandas as pd
import joblib

CLANG_REPORT_DIR = "reports/clang-report"
SCAN_STATUS_FILE = os.path.join(CLANG_REPORT_DIR, "scan-status.txt")

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

REQUIRED_FEATURE_COLUMNS = [
    "severity_score",
    "has_cwe",
    "is_null_pointer",
    "is_buffer_issue",
    "is_memory_issue",
    "is_obsolete_function",
    "is_clang",
    "alert_id",
    "severity",
    "message",
]


def fail(message, exit_code=1):
    print(f"FAILED: {message}", file=sys.stderr)
    sys.exit(exit_code)


def extract_html_reports():
    html_files = []

    for root, _, files in os.walk(CLANG_REPORT_DIR):
        for file in files:
            if file.endswith(".html") and file.startswith("report-"):
                html_files.append(os.path.join(root, file))

    return html_files


def extract_plist_reports():
    plist_files = []

    for root, _, files in os.walk(CLANG_REPORT_DIR):
        for file in files:
            if file.endswith(".plist"):
                plist_files.append(os.path.join(root, file))

    return plist_files


def read_scan_status():
    if not os.path.exists(SCAN_STATUS_FILE):
        return ""
    try:
        with open(SCAN_STATUS_FILE, "r", encoding="utf-8") as handle:
            return handle.read().strip()
    except OSError:
        return ""


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
    features = {
        "severity_score": severity_to_score(severity),
        "has_cwe": has_value(cwe),
        "is_null_pointer": keyword_feature(
            message, ["null pointer", "nullpointer"]
        ),
        "is_buffer_issue": keyword_feature(
            message, ["buffer", "overflow", "overrun", "out of bounds"]
        ),
        "is_memory_issue": keyword_feature(
            message, ["memory", "leak", "free", "dereference", "use after free", "double free"]
        ),
        "is_obsolete_function": keyword_feature(
            message, ["gets", "strcpy", "strcat", "sprintf"]
        ),
        "is_clang": 1,
        "alert_id": str(alert_id),
        "severity": str(severity),
        "message": str(message),
    }

    if list(features.keys()) != REQUIRED_FEATURE_COLUMNS:
        raise RuntimeError(
            "Runtime feature schema mismatch. "
            f"Expected {REQUIRED_FEATURE_COLUMNS}, got {list(features.keys())}."
        )

    return features


def load_model():
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(
            f"Trained model not found at {MODEL_PATH}. "
            "Run train_clang_model.py first."
        )
    try:
        model = joblib.load(MODEL_PATH)
    except Exception as exc:
        raise RuntimeError(f"Unable to load model at {MODEL_PATH}: {exc}") from exc

    if not hasattr(model, "predict"):
        raise RuntimeError("Loaded model object does not support predict().")

    return model


def validate_model_feature_compatibility(model):
    try:
        preprocessor = model.named_steps["preprocessor"]
        transformers = preprocessor.transformers
    except Exception as exc:
        raise RuntimeError(f"Unable to inspect model feature schema: {exc}") from exc

    model_columns = []
    for _, _, columns in transformers:
        if isinstance(columns, str):
            model_columns.append(columns)
        else:
            model_columns.extend(columns)

    if model_columns != REQUIRED_FEATURE_COLUMNS:
        raise RuntimeError(
            "Model expects a different feature schema. "
            f"Expected {REQUIRED_FEATURE_COLUMNS}, model has {model_columns}."
        )


def validate_runtime_environment():
    if not os.path.isdir(CLANG_REPORT_DIR):
        raise FileNotFoundError(f"Clang report directory is missing: {CLANG_REPORT_DIR}")

    html_reports = extract_html_reports()
    plist_reports = extract_plist_reports()
    scan_status = read_scan_status()

    if scan_status == "SCAN_FAILED":
        raise RuntimeError("Clang scan status indicates analyzer execution/configuration failure.")

    if not html_reports and not plist_reports:
        if scan_status == "SCAN_COMPLETED_NO_SOURCE":
            return html_reports, scan_status
        raise RuntimeError(
            "No valid Clang analyzer outputs found. "
            "Expected report-*.html or *.plist files in reports/clang-report/."
        )

    return html_reports, scan_status


def parse_clang_reports(model):
    alerts = []

    html_reports, scan_status = validate_runtime_environment()

    print(f"Found {len(html_reports)} Clang reports.")

    if not html_reports:
        # Valid analyzer structure exists (for example plist-only or no source files), but no
        # parser-usable HTML alerts were produced.
        return pd.DataFrame(alerts), scan_status

    parse_errors = []

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

            missing_columns = [
                column for column in REQUIRED_FEATURE_COLUMNS if column not in df_features.columns
            ]
            if missing_columns:
                raise RuntimeError(
                    f"Required runtime feature columns missing: {missing_columns}"
                )

            df_features = df_features[REQUIRED_FEATURE_COLUMNS]
            label = model.predict(df_features)[0]

            if label not in LABEL_MAP:
                raise RuntimeError(f"Unexpected prediction label returned by model: {label}")

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
            parse_errors.append((report_file, str(e)))

    if parse_errors and not alerts:
        first_file, first_error = parse_errors[0]
        raise RuntimeError(
            f"Malformed or unreadable Clang report. Example failure in {first_file}: {first_error}"
        )

    for report_file, error in parse_errors:
        print(f"Warning: could not parse {report_file}: {error}", file=sys.stderr)

    return pd.DataFrame(alerts), scan_status


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
    try:
        model = load_model()
        validate_model_feature_compatibility(model)

        df, scan_status = parse_clang_reports(model)
        write_prioritised_alerts(df)

        print("===== Clang Prioritised Alerts =====")

        if df.empty:
            print("COMPLETED WITH ZERO ALERTS")
            if scan_status == "SCAN_COMPLETED_NO_SOURCE":
                print("Clang scan completed with no C/C++ source files to analyze.")
            else:
                print("Valid Clang report structure found, but no usable alerts were parsed.")
            return

        print("COMPLETED WITH ALERTS")
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
    except Exception as exc:
        fail(str(exc))


if __name__ == "__main__":
    main()