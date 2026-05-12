import argparse
import joblib
import pandas as pd
from pathlib import Path


SUPPORTED_EXTENSIONS = [".c", ".cpp", ".cc", ".cxx", ".h", ".hpp"]


def read_source_files(source_dir):
    code_files = []

    for file_path in Path(source_dir).rglob("*"):
        if file_path.suffix in SUPPORTED_EXTENSIONS:
            try:
                code = file_path.read_text(encoding="utf-8", errors="ignore")
                code_files.append({
                    "file_path": str(file_path),
                    "function_code": code
                })
            except Exception as e:
                print(f"Could not read {file_path}: {e}")

    return pd.DataFrame(code_files)


def get_risk_level(probability):
    risk_score = round(probability * 100, 2)

    if risk_score >= 70:
        return risk_score, "HIGH"
    elif risk_score >= 40:
        return risk_score, "MEDIUM"
    else:
        return risk_score, "LOW"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--scan-path", required=True)
    parser.add_argument("--model-path", required=True)
    parser.add_argument("--vectorizer-path", required=True)
    parser.add_argument(
        "--output",
        default="reports/commit_risk/commit_risk_report.csv"
    )

    args = parser.parse_args()

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    model = joblib.load(args.model_path)
    vectorizer = joblib.load(args.vectorizer_path)

    df = read_source_files(args.scan_path)

    if df.empty:
        print("No C/C++ source files found for commit risk prediction.")
        pd.DataFrame(columns=["file_path", "risk_score", "risk_level"]).to_csv(
            output_path,
            index=False
        )
        return

    X = vectorizer.transform(df["function_code"])
    probabilities = model.predict_proba(X)[:, 1]

    results = []

    for index, row in df.iterrows():
        risk_score, risk_level = get_risk_level(probabilities[index])

        results.append({
            "file_path": row["file_path"],
            "risk_score": risk_score,
            "risk_level": risk_level
        })

    report_df = pd.DataFrame(results)
    report_df.to_csv(output_path, index=False)

    print("\nCommit Risk Prediction Completed")
    print(report_df)
    print(f"\nReport saved to: {output_path}")


if __name__ == "__main__":
    main()