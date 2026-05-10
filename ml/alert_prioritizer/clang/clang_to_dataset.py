import os
import re
import pandas as pd
from pathlib import Path

RAW_OUTPUT_DIR = Path("reports/alert_prioritizer/clang/raw_outputs")
OUTPUT_FILE = Path("data/processed/alert_prioritizer/clang/clang_alert_dataset.csv")


def extract_cwe_from_filename(filename):
    match = re.search(r"(CWE\d+)", filename)
    return match.group(1).replace("CWE", "") if match else ""


def assign_priority(severity, message, cwe):
    text = f"{severity} {message} {cwe}".lower()

    high_keywords = [
        "null pointer",
        "dereference",
        "use after free",
        "double free",
        "buffer overflow",
        "memory leak",
        "dead store",
    ]

    if severity.lower() == "error":
        return "HIGH"

    if any(keyword in text for keyword in high_keywords):
        return "HIGH"

    if severity.lower() == "warning":
        return "MEDIUM"

    return "LOW"


def label_from_priority(priority):
    return {
        "LOW": 0,
        "MEDIUM": 1,
        "HIGH": 2
    }.get(priority, 0)


def parse_txt_file(txt_file):
    alerts = []
    cwe = extract_cwe_from_filename(txt_file.name)

    with open(txt_file, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    for line in lines:
        # Example:
        # path/file.c:10:5: warning: message text
        match = re.search(r"(.+?):(\d+):\d+:\s+(warning|error|note):\s+(.+)", line)

        if match:
            file_path = match.group(1)
            line_number = match.group(2)
            severity = match.group(3)
            message = match.group(4).strip()

            if severity == "note":
                continue

            alert_id = message.split(":")[0][:60]

            priority = assign_priority(severity, message, cwe)

            alerts.append({
                "tool": "clang",
                "file": file_path,
                "line": line_number,
                "alert_id": alert_id,
                "cwe": cwe,
                "severity": severity,
                "message": message,
                "priority": priority,
                "label": label_from_priority(priority)
            })

    return alerts


def main():
    all_alerts = []

    if not RAW_OUTPUT_DIR.exists():
        print(f"Raw output folder not found: {RAW_OUTPUT_DIR}")
        return

    txt_files = list(RAW_OUTPUT_DIR.glob("*.txt"))

    print(f"Found {len(txt_files)} Clang raw output files.")

    for txt_file in txt_files:
        alerts = parse_txt_file(txt_file)
        all_alerts.extend(alerts)

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    df = pd.DataFrame(all_alerts)

    if df.empty:
        print("No Clang alerts found. Empty dataset created.")
        df = pd.DataFrame(columns=[
            "tool", "file", "line", "alert_id", "cwe",
            "severity", "message", "priority", "label"
        ])

    df.to_csv(OUTPUT_FILE, index=False)

    print(f"Clang alert dataset created: {OUTPUT_FILE}")
    print(f"Total alerts extracted: {len(df)}")
    print("\nPriority distribution:")
    if not df.empty:
        print(df["priority"].value_counts())


if __name__ == "__main__":
    main()