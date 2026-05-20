import json
import time
import joblib
import pandas as pd
from pathlib import Path

from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler


HISTORY_FILE = Path(".devsecops/anomaly_detection/pipeline_metrics.csv")
MODEL_DIR = Path(".devsecops/anomaly_detection/models")
REPORT_DIR = Path("reports/anomaly_detection")

MODEL_PATH = MODEL_DIR / "anomaly_model.pkl"
SCALER_PATH = MODEL_DIR / "anomaly_scaler.pkl"
METADATA_PATH = MODEL_DIR / "anomaly_model_metadata.json"
COMPARISON_REPORT = REPORT_DIR / "anomaly_model_comparison.csv"

MIN_ROWS = 30

FEATURE_COLUMNS = [
    "total_files_scanned",
    "total_alerts",
    "high_alerts",
    "medium_alerts",
    "low_alerts",
    "high_commit_risk",
    "medium_commit_risk",
    "low_commit_risk",
    "alerts_per_file"
]


def load_dataset():
    if not HISTORY_FILE.exists():
        print(f"Metrics history not found: {HISTORY_FILE}")
        return pd.DataFrame()

    df = pd.read_csv(HISTORY_FILE)

    for col in FEATURE_COLUMNS:
        if col not in df.columns:
            df[col] = 0

    df[FEATURE_COLUMNS] = df[FEATURE_COLUMNS].fillna(0)

    return df


def evaluate_model(name, model, X):
    start_time = time.time()

    if name == "LOF":
        predictions = model.fit_predict(X)
        scores = model.negative_outlier_factor_
    else:
        model.fit(X)
        predictions = model.predict(X)
        scores = model.decision_function(X)

    execution_time = round(time.time() - start_time, 4)
    anomaly_count = int((predictions == -1).sum())
    normal_count = int((predictions == 1).sum())
    anomaly_rate = round(anomaly_count / len(predictions), 4)

    return {
        "model": name,
        "normal_count": normal_count,
        "anomaly_count": anomaly_count,
        "anomaly_rate": anomaly_rate,
        "execution_time_seconds": execution_time,
        "score_min": round(float(min(scores)), 4),
        "score_max": round(float(max(scores)), 4)
    }


def main():
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    df = load_dataset()

    if df.empty:
        print("No ML3 metrics available for training.")
        return

    if len(df) < MIN_ROWS:
        print(f"Not enough ML3 history for training. Current rows: {len(df)} / {MIN_ROWS}")
        return

    X = df[FEATURE_COLUMNS]

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    models = {
        "Isolation Forest": IsolationForest(
            n_estimators=100,
            contamination=0.10,
            random_state=42
        ),
        "One-Class SVM": OneClassSVM(
            kernel="rbf",
            nu=0.10,
            gamma="scale"
        ),
        "LOF": LocalOutlierFactor(
            n_neighbors=10,
            contamination=0.10
        )
    }

    results = []

    for name, model in models.items():
        print(f"Training and evaluating {name}...")
        result = evaluate_model(name, model, X_scaled)
        results.append(result)

    results_df = pd.DataFrame(results)
    results_df.to_csv(COMPARISON_REPORT, index=False)

    final_model = IsolationForest(
        n_estimators=100,
        contamination=0.10,
        random_state=42
    )

    final_model.fit(X_scaled)

    joblib.dump(final_model, MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)

    metadata = {
        "selected_model": "Isolation Forest",
        "reason": "Selected for lightweight CI/CD integration, scalability, and stable unsupervised anomaly detection.",
        "training_rows": len(df),
        "features": FEATURE_COLUMNS
    }

    with open(METADATA_PATH, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=4)

    print("\nML3 anomaly model training completed.")
    print(f"Training rows: {len(df)}")
    print(f"Model saved to: {MODEL_PATH}")
    print(f"Scaler saved to: {SCALER_PATH}")
    print(f"Comparison report saved to: {COMPARISON_REPORT}")


if __name__ == "__main__":
    main()