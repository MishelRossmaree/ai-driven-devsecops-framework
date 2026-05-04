import csv
import os
import xml.etree.ElementTree as ET
import pandas as pd
import joblib

CPPCHECK_REPORT = "reports/cppcheck-report.xml"
MODEL_PATH = "models/alert_priority_model.pkl"
OUTPUT_FILE = "reports/prioritised-alerts.csv"

LABEL_MAP = {
    0: "LOW",
    1: "MEDIUM",
    2: "HIGH"
}

IGNORED_ALERT_IDS = {
    "checkersReport"
}


def severity_to_score(severity):
    severity = str(severity).lower()

    mapping = {
        "critical": 4,
        "error": 3,
        "warning": 2,
        "performance": 2,
        "portability": 2,
        "style": 1,
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


def parse_cppcheck_report():
    alerts = []

    if not os.path.exists(CPPCHECK_REPORT):
        print("Cppcheck report not found.")
        return alerts

    tree = ET.parse(CPPCHECK_REPORT)
    root = tree.getroot()

    for error in root.findall(".//error"):
        alert_id = error.get("id", "")
        severity = error.get("severity", "")
        message = error.get("msg", "")
        cwe = error.get("cwe", "")

        if alert_id in IGNORED_ALERT_IDS:
            continue

        location = error.find("location")
        file_name = location.get("file", "") if location is not None else ""
        line = location.get("line", "") if location is not None else ""

        alerts.append({
            "tool": "cppcheck",
            "file": file_name,
            "line": line,
            "alert_id": alert_id,
            "cwe": cwe,
            "severity": severity,
            "message": message,
        })

    return alerts


def prepare_features(alerts):
    df = pd.DataFrame(alerts)

    if df.empty:
        return df

    df["message"] = df["message"].fillna("")
    df["alert_id"] = df["alert_id"].fillna("")
    df["severity"] = df["severity"].fillna("")
    df["cwe"] = df["cwe"].fillna(0).astype(str)

    df["severity_score"] = df["severity"].apply(severity_to_score)
    df["has_cwe"] = df["cwe"].apply(has_value)

    df["is_null_pointer"] = df["message"].apply(
        lambda x: keyword_feature(x, ["null pointer", "nullpointer", "null"])
    )

    df["is_buffer_issue"] = df["message"].apply(
        lambda x: keyword_feature(x, ["buffer", "overflow", "overrun"])
    )

    df["is_memory_issue"] = df["message"].apply(
        lambda x: keyword_feature(x, ["memory", "memleak", "leak", "free", "dereference"])
    )

    df["is_obsolete_function"] = df["message"].apply(
        lambda x: keyword_feature(x, ["gets", "strcpy", "strcat", "sprintf"])
    )

    df["is_cppcheck"] = 1

    return df


def predict_priorities(df):
    if df.empty:
        return df

    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(
            f"Model file not found: {MODEL_PATH}. "
            "Please train the model first and commit models/alert_priority_model.pkl."
        )

    model = joblib.load(MODEL_PATH)

    features = [
        "severity_score",
        "has_cwe",
        "is_null_pointer",
        "is_buffer_issue",
        "is_memory_issue",
        "is_obsolete_function",
        "is_cppcheck",
        "alert_id",
        "severity",
        "cwe",
        "message",
    ]

    predictions = model.predict(df[features])

    df["predicted_label"] = predictions
    df["priority"] = df["predicted_label"].map(LABEL_MAP)

    return df


def write_prioritised_alerts(df):
    os.makedirs("reports", exist_ok=True)

    if df.empty:
        with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow([
                "priority",
                "tool",
                "file",
                "line",
                "alert_id",
                "cwe",
                "severity",
                "message"
            ])

        print("No alerts found. Empty prioritised report created.")
        return

    priority_order = {
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1
    }

    df["priority_rank"] = df["priority"].map(priority_order)
    df = df.sort_values(by="priority_rank", ascending=False)

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

    df[output_columns].to_csv(OUTPUT_FILE, index=False)

    print(f"ML prioritised alerts generated: {OUTPUT_FILE}")


def main():
    alerts = parse_cppcheck_report()
    df = prepare_features(alerts)
    df = predict_priorities(df)
    write_prioritised_alerts(df)

    print("===== ML Prioritised Alerts =====")

    if df.empty:
        print("No real alerts found.")
        return

    for _, alert in df.iterrows():
        cwe_text = f"CWE-{alert['cwe']}" if alert["cwe"] else "No CWE"
        print(
            f"{alert['priority']} | {alert['tool']} | "
            f"{alert['file']}:{alert['line']} | "
            f"{alert['alert_id']} | {cwe_text}"
        )


if __name__ == "__main__":
    main()