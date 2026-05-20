import json
import joblib
import pandas as pd
from pathlib import Path


HISTORY_FILE = Path(".devsecops/anomaly_detection/pipeline_metrics.csv")
MODEL_PATH = Path(".devsecops/anomaly_detection/models/anomaly_model.pkl")
SCALER_PATH = Path(".devsecops/anomaly_detection/models/anomaly_scaler.pkl")
METADATA_PATH = Path(".devsecops/anomaly_detection/models/anomaly_model_metadata.json")

REPORT_DIR = Path("reports/anomaly_detection")
REPORT_FILE = REPORT_DIR / "anomaly_report.csv"

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


def main():
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    if not HISTORY_FILE.exists():
        print("No pipeline metrics history found. Skipping anomaly detection.")
        return

    if not MODEL_PATH.exists() or not SCALER_PATH.exists():
        print("No trained ML3 anomaly model found. Skipping anomaly detection.")
        return

    df = pd.read_csv(HISTORY_FILE)

    if df.empty:
        print("Pipeline metrics history is empty. Skipping anomaly detection.")
        return

    for col in FEATURE_COLUMNS:
        if col not in df.columns:
            df[col] = 0

    latest_row = df.tail(1).copy()
    X_latest = latest_row[FEATURE_COLUMNS].fillna(0)

    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)

    X_scaled = scaler.transform(X_latest)

    prediction = model.predict(X_scaled)[0]
    score = model.decision_function(X_scaled)[0]

    anomaly_status = "ANOMALOUS" if prediction == -1 else "NORMAL"

    selected_model = "Unknown"

    if METADATA_PATH.exists():
        with open(METADATA_PATH, "r", encoding="utf-8") as f:
            metadata = json.load(f)
            selected_model = metadata.get("selected_model", "Unknown")

    result = {
        "model": selected_model,
        "anomaly_status": anomaly_status,
        "anomaly_score": round(float(score), 4),
        "total_files_scanned": int(latest_row["total_files_scanned"].iloc[0]),
        "total_alerts": int(latest_row["total_alerts"].iloc[0]),
        "high_alerts": int(latest_row["high_alerts"].iloc[0]),
        "medium_alerts": int(latest_row["medium_alerts"].iloc[0]),
        "low_alerts": int(latest_row["low_alerts"].iloc[0]),
        "high_commit_risk": int(latest_row["high_commit_risk"].iloc[0]),
        "medium_commit_risk": int(latest_row["medium_commit_risk"].iloc[0]),
        "low_commit_risk": int(latest_row["low_commit_risk"].iloc[0]),
        "alerts_per_file": float(latest_row["alerts_per_file"].iloc[0])
    }

    pd.DataFrame([result]).to_csv(REPORT_FILE, index=False)

    print("\nML3 Pipeline Anomaly Detection Completed")
    print(f"Status: {anomaly_status}")
    print(f"Score: {round(float(score), 4)}")
    print(f"Report saved to: {REPORT_FILE}")


if __name__ == "__main__":
    main()