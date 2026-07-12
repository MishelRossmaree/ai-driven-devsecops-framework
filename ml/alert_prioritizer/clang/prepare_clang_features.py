from pathlib import Path

import pandas as pd

ANNOTATION_FILE = Path("data/processed/alert_prioritizer/clang/clang_alert_annotation.csv")
TRAINING_OUTPUT_FILE = Path("data/processed/alert_prioritizer/clang/clang_alert_training.csv")
FEATURE_OUTPUT_FILE = Path("data/processed/alert_prioritizer/clang/clang_alert_features.csv")

HIGH_CWE_FAMILIES = {
    "CWE121_Stack_Based_Buffer_Overflow",
    "CWE122_Heap_Based_Buffer_Overflow",
    "CWE415_Double_Free",
    "CWE416_Use_After_Free",
}
MEDIUM_CWE_FAMILY = "CWE476_NULL_Pointer_Dereference"


def severity_to_score(severity):
    mapping = {
        "critical": 4,
        "error": 3,
        "warning": 2,
        "note": 1,
        "information": 1,
    }
    return mapping.get(str(severity).lower(), 0)


def has_value(value):
    if pd.isna(value):
        return 0
    value = str(value).strip().lower()
    return 0 if value in {"", "nan", "none", "null"} else 1


def keyword_feature(text, keywords):
    lowered = str(text).lower()
    return int(any(keyword in lowered for keyword in keywords))


def derive_priority_and_label(row):
    ground_truth = str(row.get("ground_truth_status", "")).strip().lower()
    cwe_family = str(row.get("juliet_cwe_family", "")).strip()

    if ground_truth == "good":
        return "LOW", 0

    if ground_truth == "bad" and cwe_family == MEDIUM_CWE_FAMILY:
        return "MEDIUM", 1

    if ground_truth == "bad" and cwe_family in HIGH_CWE_FAMILIES:
        return "HIGH", 2

    return "UNKNOWN", pd.NA


def main():
    df = pd.read_csv(ANNOTATION_FILE)

    if df.empty:
        raise ValueError(f"Annotation dataset is empty: {ANNOTATION_FILE}")

    for column in ["message", "alert_id", "severity", "cwe", "juliet_cwe_family", "ground_truth_status"]:
        if column not in df.columns:
            raise ValueError(f"Required column missing from annotation dataset: {column}")

    priorities = df.apply(derive_priority_and_label, axis=1, result_type="expand")
    priorities.columns = ["priority", "label"]
    df = pd.concat([df, priorities], axis=1)

    df["message"] = df["message"].fillna("")
    df["alert_id"] = df["alert_id"].fillna("")
    df["severity"] = df["severity"].fillna("")
    df["cwe"] = df["cwe"].fillna("")

    df["severity_score"] = df["severity"].apply(severity_to_score)
    df["has_cwe"] = df["cwe"].apply(has_value)
    df["is_null_pointer"] = df["message"].apply(lambda value: keyword_feature(value, ["null pointer", "nullpointer"]))
    df["is_buffer_issue"] = df["message"].apply(lambda value: keyword_feature(value, ["buffer", "overflow", "overrun", "out of bounds"]))
    df["is_memory_issue"] = df["message"].apply(lambda value: keyword_feature(value, ["memory", "leak", "free", "dereference", "use after free", "double free"]))
    df["is_obsolete_function"] = df["message"].apply(lambda value: keyword_feature(value, ["gets", "strcpy", "strcat", "sprintf"]))
    df["is_clang"] = 1

    TRAINING_OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(TRAINING_OUTPUT_FILE, index=False)
    df.to_csv(FEATURE_OUTPUT_FILE, index=False)

    priority_counts = df["priority"].value_counts(dropna=False)
    unknown_count = int((df["priority"] == "UNKNOWN").sum())

    print(f"Labeled training dataset created: {TRAINING_OUTPUT_FILE}")
    print(f"Feature dataset created: {FEATURE_OUTPUT_FILE}")
    print(f"Total rows: {len(df)}")
    print("Priority distribution:")
    print(priority_counts)
    print(f"Excluded unknown count (for model training): {unknown_count}")


if __name__ == "__main__":
    main()