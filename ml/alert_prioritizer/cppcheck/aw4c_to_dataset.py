import os
import pandas as pd

ACTIONABLE_FILE = "data/raw/alert_prioritizer/cppcheck/compressed_ActionableWarning.json.gz"
NON_ACTIONABLE_FILE = "data/raw/alert_prioritizer/cppcheck/compressed_NonActionableWarning.json.gz"
OUTPUT_FILE = "data/processed/alert_prioritizer/cppcheck/aw4c_alert_dataset.csv"

# Exact duplicate alert identity fields used for dataset deduplication.
DUPLICATE_ID_FIELDS = [
    "tool",
    "file",
    "line",
    "alert_id",
    "cwe",
    "severity",
    "message",
    "is_actionable",
    "priority",
    "label",
]


def load_aw4c_json(path):
    if not os.path.exists(path):
        raise FileNotFoundError(f"File not found: {path}")
    return pd.read_json(path, compression="gzip")


def assign_priority(is_actionable, severity):
    severity = str(severity).lower()

    if not is_actionable:
        return "LOW"

    if severity in ["error", "critical"]:
        return "HIGH"

    return "MEDIUM"


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
    if pd.isna(value):
        return 0
    value = str(value).strip()
    return 0 if value == "" or value.lower() in ["nan", "none", "null"] else 1


def keyword_feature(text, keywords):
    text = str(text).lower()
    return int(any(keyword in text for keyword in keywords))


def transform_dataset(df, is_actionable):
    output = pd.DataFrame()

    output["tool"] = df["toolName"]
    output["file"] = df["filePath"]
    output["line"] = pd.to_numeric(df["lineNumber"], errors="coerce")
    output["alert_id"] = df["warningType"]
    output["cwe"] = df["cwe"]
    output["severity"] = df["warningSeverity"]
    output["message"] = df["warningMessage"]

    output["is_actionable"] = 1 if is_actionable else 0

    output["priority"] = output["severity"].apply(
        lambda sev: assign_priority(is_actionable, sev)
    )

    output["label"] = output["priority"].map({
        "LOW": 0,
        "MEDIUM": 1,
        "HIGH": 2
    })

    output["severity_score"] = output["severity"].apply(severity_to_score)
    output["has_cwe"] = output["cwe"].apply(has_value)

    output["is_null_pointer"] = output["message"].apply(
        lambda x: keyword_feature(x, ["null pointer", "nullpointer", "null"])
    )

    output["is_buffer_issue"] = output["message"].apply(
        lambda x: keyword_feature(x, ["buffer", "overflow", "overrun"])
    )

    output["is_memory_issue"] = output["message"].apply(
        lambda x: keyword_feature(x, ["memory", "memleak", "leak", "free", "dereference"])
    )

    output["is_obsolete_function"] = output["message"].apply(
        lambda x: keyword_feature(x, ["gets", "strcpy", "strcat", "sprintf"])
    )

    output["is_cppcheck"] = output["tool"].apply(
        lambda x: 1 if "cppcheck" in str(x).lower() else 0
    )

    return output


def main():
    os.makedirs("data/processed", exist_ok=True)

    actionable_df = load_aw4c_json(ACTIONABLE_FILE)
    non_actionable_df = load_aw4c_json(NON_ACTIONABLE_FILE)

    actionable_out = transform_dataset(actionable_df, is_actionable=True)
    non_actionable_out = transform_dataset(non_actionable_df, is_actionable=False)

    final_df = pd.concat([actionable_out, non_actionable_out], ignore_index=True)

    before_dedup = len(final_df)
    final_df = final_df.drop_duplicates(subset=DUPLICATE_ID_FIELDS, keep="first")
    after_dedup = len(final_df)

    final_df.to_csv(OUTPUT_FILE, index=False)

    print(f"Dataset created successfully: {OUTPUT_FILE}")
    print("Dataset shape:", final_df.shape)
    print(f"Rows before deduplication: {before_dedup}")
    print(f"Rows after deduplication: {after_dedup}")
    print(f"Duplicate rows removed: {before_dedup - after_dedup}")
    print(f"Deduplication fields: {DUPLICATE_ID_FIELDS}")
    print("\nPriority distribution:")
    print(final_df["priority"].value_counts())


if __name__ == "__main__":
    main()