import pandas as pd
from pathlib import Path

INPUT_FILE = Path("data/processed/alert_prioritizer/clang/clang_alert_dataset.csv")
OUTPUT_FILE = Path("data/processed/alert_prioritizer/clang/clang_alert_features.csv")


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
    if pd.isna(value):
        return 0

    value = str(value).strip()

    if value == "" or value.lower() in ["nan", "none", "null"]:
        return 0

    return 1


def keyword_feature(text, keywords):
    text = str(text).lower()
    return int(any(keyword in text for keyword in keywords))


def main():
    df = pd.read_csv(INPUT_FILE)

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
        lambda x: keyword_feature(x, ["buffer", "overflow", "overrun", "out of bounds"])
    )

    df["is_memory_issue"] = df["message"].apply(
        lambda x: keyword_feature(x, ["memory", "memleak", "leak", "free", "dereference"])
    )

    df["is_obsolete_function"] = df["message"].apply(
        lambda x: keyword_feature(x, ["gets", "strcpy", "strcat", "sprintf"])
    )

    df["is_cppcheck"] = 0
    df["is_clang"] = 1

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(OUTPUT_FILE, index=False)

    print(f"Clang feature dataset created: {OUTPUT_FILE}")
    print("Dataset shape:", df.shape)
    print("\nPriority distribution:")
    print(df["priority"].value_counts())


if __name__ == "__main__":
    main()