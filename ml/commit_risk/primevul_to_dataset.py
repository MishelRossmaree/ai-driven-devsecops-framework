import json
import pandas as pd
from pathlib import Path


RAW_DATA_DIR = Path("data/raw/commit_risk")
OUTPUT_DIR = Path("data/processed/commit_risk")

DATA_FILES = {
    "primevul_train.jsonl": "train.csv",
    "primevul_valid.jsonl": "valid.csv",
    "primevul_test.jsonl": "test.csv"
}


def load_primevul_jsonl(file_path):
    rows = []

    with open(file_path, "r", encoding="utf-8") as file:
        for line in file:
            if line.strip():
                rows.append(json.loads(line))

    return rows


def convert_primevul_to_dataset(records, split_name):
    dataset_rows = []

    for item in records:
        dataset_rows.append({
            "split": split_name,
            "project": item.get("project", ""),
            "commit_id": item.get("commit_id", ""),
            "cve": item.get("cve", ""),
            "cwe": item.get("cwe", ""),
            "function_code": item.get("func", ""),
            "target": item.get("target", 0)
        })

    return pd.DataFrame(dataset_rows)


def process_file(input_file, output_file):
    input_path = RAW_DATA_DIR / input_file
    output_path = OUTPUT_DIR / output_file

    split_name = output_file.replace(".csv", "")

    records = load_primevul_jsonl(input_path)
    df = convert_primevul_to_dataset(records, split_name)

    df = df.dropna(subset=["function_code", "target"])
    df = df.drop_duplicates(subset=["function_code"])

    df.to_csv(output_path, index=False)

    print(f"\nProcessed {input_file}")
    print(f"Saved to: {output_path}")
    print(f"Rows: {len(df)}")
    print("Target distribution:")
    print(df["target"].value_counts())


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    for input_file, output_file in DATA_FILES.items():
        process_file(input_file, output_file)

    print("\nPRIMEVUL train/valid/test conversion completed successfully")


if __name__ == "__main__":
    main()