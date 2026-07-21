import os
import json
import time
import hashlib
import platform
import joblib
import sklearn
import numpy as np
import pandas as pd
from pathlib import Path

from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    average_precision_score
)


HISTORY_FILE = Path(".devsecops/anomaly_detection/pipeline_metrics.csv")
MODEL_DIR = Path(".devsecops/anomaly_detection/models")
REPORT_DIR = Path("reports/anomaly_detection")

MODEL_PATH = MODEL_DIR / "anomaly_model.pkl"
SCALER_PATH = MODEL_DIR / "anomaly_scaler.pkl"
METADATA_PATH = MODEL_DIR / "anomaly_model_metadata.json"
COMPARISON_REPORT = REPORT_DIR / "anomaly_model_comparison.csv"
SYNTHETIC_EVALUATION_REPORT = REPORT_DIR / "synthetic_evaluation.csv"
SYNTHETIC_EVALUATION_SUMMARY = REPORT_DIR / "synthetic_evaluation_summary.json"

DEFAULT_MIN_ROWS = 30
RANDOM_SEED = 42
HOLDOUT_RATIO = 0.2

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

NON_DEPLOYABLE_MODELS = {"LOF"}

STATUS_OK = "OK"
STATUS_MISSING = "MISSING"
STATUS_MALFORMED = "MALFORMED"
STATUS_SCHEMA_MISMATCH = "SCHEMA_MISMATCH"

UPSTREAM_STATUS_COLUMNS = [
    "commit_risk_status",
    "commit_summary_status",
    "cppcheck_status",
    "clang_status"
]

PERTURBATION_RECIPE = {
    "total_alerts_multiplier": [2.0, 4.0],
    "high_alerts_increment": [3, 15],
    "high_commit_risk_increment": [2, 10],
    "alerts_per_file_multiplier": [2.0, 3.0],
    "total_files_scanned_shrink_ratio": [0.35, 0.7]
}


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


def to_bool(value):
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "y"}


def normalise_status(value):
    return str(value).strip().upper()


def filter_valid_training_rows(df):
    if df.empty:
        return df, {
            "TOTAL_ROWS": 0
        }

    exclusion_reasons = {}
    valid_mask = pd.Series(True, index=df.index)

    if "ml3_scoring_blocked" in df.columns:
        blocked_mask = df["ml3_scoring_blocked"].apply(to_bool)
        blocked_count = int(blocked_mask.sum())
        if blocked_count > 0:
            exclusion_reasons["ML3_SCORING_BLOCKED"] = blocked_count
        valid_mask &= ~blocked_mask

    for status_col in UPSTREAM_STATUS_COLUMNS:
        if status_col not in df.columns:
            continue

        status_series = df[status_col].apply(normalise_status)
        for invalid_status in [STATUS_MISSING, STATUS_MALFORMED, STATUS_SCHEMA_MISMATCH]:
            status_mask = status_series.eq(invalid_status)
            count = int(status_mask.sum())
            if count > 0:
                exclusion_reasons[f"{status_col}:{invalid_status}"] = count
            valid_mask &= ~status_mask

    ml3_outcome_col = None
    if "ml3_outcome" in df.columns:
        ml3_outcome_col = "ml3_outcome"
    elif "anomaly_status" in df.columns:
        ml3_outcome_col = "anomaly_status"

    if ml3_outcome_col is not None:
        failed_mask = df[ml3_outcome_col].apply(normalise_status).eq("FAILED")
        failed_count = int(failed_mask.sum())
        if failed_count > 0:
            exclusion_reasons["ML3_OUTCOME_FAILED"] = failed_count
        valid_mask &= ~failed_mask

    valid_df = df[valid_mask].copy()
    exclusion_reasons["TOTAL_ROWS"] = int(len(df))
    exclusion_reasons["VALID_ROWS"] = int(len(valid_df))
    exclusion_reasons["EXCLUDED_ROWS"] = int(len(df) - len(valid_df))

    return valid_df, exclusion_reasons


def hash_training_data(df):
    raw = df[FEATURE_COLUMNS].copy()
    hash_value = pd.util.hash_pandas_object(raw, index=True).values.tobytes()
    return hashlib.sha256(hash_value).hexdigest()


def get_min_rows():
    value = os.environ.get("ML3_MIN_ROWS", str(DEFAULT_MIN_ROWS)).strip()

    try:
        parsed = int(value)
        if parsed <= 0:
            raise ValueError
        return parsed
    except Exception:
        print(
            f"Invalid ML3_MIN_ROWS='{value}'. Falling back to {DEFAULT_MIN_ROWS}."
        )
        return DEFAULT_MIN_ROWS


def write_status_report(status, rows_available, min_rows, reason):
    status_row = {
        "status": status,
        "rows_available": rows_available,
        "min_rows_required": min_rows,
        "reason": reason,
        "model": "",
        "normal_count": "",
        "anomaly_count": "",
        "anomaly_rate": "",
        "execution_time_seconds": "",
        "score_min": "",
        "score_max": ""
    }

    comparison_row = status_row.copy()
    comparison_row.update({
        "deployment_eligible": "",
        "precision": "",
        "recall": "",
        "f1": "",
        "false_positive_rate": "",
        "tn": "",
        "fp": "",
        "fn": "",
        "tp": "",
        "pr_auc": "",
        "exploratory_only": "",
        "selection_rank": ""
    })

    pd.DataFrame([comparison_row]).to_csv(COMPARISON_REPORT, index=False)

    pd.DataFrame([
        {
            "status": status,
            "model": "NOT_AVAILABLE",
            "deployment_eligible": False,
            "precision": "",
            "recall": "",
            "f1": "",
            "false_positive_rate": "",
            "tn": "",
            "fp": "",
            "fn": "",
            "tp": "",
            "pr_auc": "",
            "execution_time_seconds": "",
            "normal_examples": "",
            "synthetic_anomalies": "",
            "seed": RANDOM_SEED,
            "exploratory_only": "",
            "reason": reason
        }
    ]).to_csv(SYNTHETIC_EVALUATION_REPORT, index=False)

    with open(SYNTHETIC_EVALUATION_SUMMARY, "w", encoding="utf-8") as f:
        json.dump(
            {
                "status": status,
                "reason": reason,
                "seed": RANDOM_SEED,
                "normal_examples": 0,
                "synthetic_anomalies": 0,
                "selected_model": "NOT_AVAILABLE",
                "selection_policy": [
                    "anomaly_f1_desc",
                    "anomaly_recall_desc",
                    "false_positive_rate_asc",
                    "execution_time_seconds_asc"
                ],
                "perturbation_recipe": PERTURBATION_RECIPE
            },
            f,
            indent=4
        )


def evaluate_model_in_sample(name, model, X):
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


def split_train_holdout(df):
    holdout_size = max(1, int(round(len(df) * HOLDOUT_RATIO)))
    holdout_size = min(holdout_size, len(df) - 1)

    if holdout_size <= 0:
        holdout_size = 1

    train_df = df.iloc[:-holdout_size].copy()
    holdout_df = df.iloc[-holdout_size:].copy()

    if train_df.empty:
        train_df = df.iloc[:-1].copy()
        holdout_df = df.iloc[-1:].copy()

    return train_df, holdout_df


def create_synthetic_anomalies(holdout_features):
    rng = np.random.RandomState(RANDOM_SEED)
    synthetic = holdout_features.copy()

    total_alert_multiplier = rng.uniform(
        PERTURBATION_RECIPE["total_alerts_multiplier"][0],
        PERTURBATION_RECIPE["total_alerts_multiplier"][1],
        len(synthetic)
    )
    alerts_per_file_multiplier = rng.uniform(
        PERTURBATION_RECIPE["alerts_per_file_multiplier"][0],
        PERTURBATION_RECIPE["alerts_per_file_multiplier"][1],
        len(synthetic)
    )
    file_shrink_ratio = rng.uniform(
        PERTURBATION_RECIPE["total_files_scanned_shrink_ratio"][0],
        PERTURBATION_RECIPE["total_files_scanned_shrink_ratio"][1],
        len(synthetic)
    )

    high_alert_increment = rng.randint(
        PERTURBATION_RECIPE["high_alerts_increment"][0],
        PERTURBATION_RECIPE["high_alerts_increment"][1] + 1,
        len(synthetic)
    )
    high_risk_increment = rng.randint(
        PERTURBATION_RECIPE["high_commit_risk_increment"][0],
        PERTURBATION_RECIPE["high_commit_risk_increment"][1] + 1,
        len(synthetic)
    )

    synthetic["total_alerts"] = (
        synthetic["total_alerts"] * total_alert_multiplier
    ).round().astype(int)
    synthetic["high_alerts"] = (
        synthetic["high_alerts"] + high_alert_increment
    ).round().astype(int)
    synthetic["high_commit_risk"] = (
        synthetic["high_commit_risk"] + high_risk_increment
    ).round().astype(int)

    synthetic["total_files_scanned"] = (
        synthetic["total_files_scanned"] * file_shrink_ratio
    ).round().astype(int)
    synthetic["total_files_scanned"] = synthetic["total_files_scanned"].clip(lower=1)

    synthetic["medium_alerts"] = synthetic["medium_alerts"].clip(lower=0).round().astype(int)
    synthetic["low_alerts"] = synthetic["low_alerts"].clip(lower=0).round().astype(int)
    synthetic["medium_commit_risk"] = synthetic["medium_commit_risk"].clip(lower=0).round().astype(int)
    synthetic["low_commit_risk"] = synthetic["low_commit_risk"].clip(lower=0).round().astype(int)

    synthetic["alerts_per_file"] = (
        synthetic["alerts_per_file"] * alerts_per_file_multiplier
    ).round(2)

    return synthetic


def evaluate_on_synthetic(name, model, X_train, X_eval, y_true, deployable=True):
    start_time = time.time()

    model.fit(X_train)
    predictions_raw = model.predict(X_eval)
    predictions = np.where(predictions_raw == -1, 1, 0)

    if hasattr(model, "decision_function"):
        scores_raw = model.decision_function(X_eval)
        anomaly_scores = -scores_raw
    else:
        anomaly_scores = np.where(predictions == 1, 1.0, 0.0)

    execution_time = round(time.time() - start_time, 4)

    precision = precision_score(y_true, predictions, zero_division=0)
    recall = recall_score(y_true, predictions, zero_division=0)
    f1 = f1_score(y_true, predictions, zero_division=0)
    tn, fp, fn, tp = confusion_matrix(y_true, predictions, labels=[0, 1]).ravel()

    if (fp + tn) > 0:
        false_positive_rate = fp / (fp + tn)
    else:
        false_positive_rate = 0.0

    try:
        pr_auc = average_precision_score(y_true, anomaly_scores)
    except Exception:
        pr_auc = 0.0

    return {
        "model": name,
        "deployment_eligible": bool(deployable),
        "precision": round(float(precision), 4),
        "recall": round(float(recall), 4),
        "f1": round(float(f1), 4),
        "false_positive_rate": round(float(false_positive_rate), 4),
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp),
        "pr_auc": round(float(pr_auc), 4),
        "execution_time_seconds": execution_time,
        "normal_examples": int((y_true == 0).sum()),
        "synthetic_anomalies": int((y_true == 1).sum()),
        "seed": RANDOM_SEED,
        "exploratory_only": not deployable,
        "selection_rank": None,
        "reason": ""
    }


def select_model(results_df):
    eligible = results_df[results_df["deployment_eligible"] == True].copy()

    if eligible.empty:
        return None

    eligible = eligible.sort_values(
        by=["f1", "recall", "false_positive_rate", "execution_time_seconds"],
        ascending=[False, False, True, True]
    )
    eligible["selection_rank"] = range(1, len(eligible) + 1)

    return eligible


def main():
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    df = load_dataset()
    min_rows = get_min_rows()
    total_history_rows = int(len(df))

    if df.empty:
        print("No ML3 metrics available for training.")
        write_status_report(
            status="SKIPPED",
            rows_available=0,
            min_rows=min_rows,
            reason="No ML3 metrics history found"
        )
        return

    valid_df, exclusion_reasons = filter_valid_training_rows(df)
    valid_training_rows = int(len(valid_df))
    excluded_history_rows = int(total_history_rows - valid_training_rows)

    if valid_df.empty:
        reason = "No valid historical rows available after ML3 training filters"
        print(reason)
        write_status_report(
            status="SKIPPED",
            rows_available=0,
            min_rows=min_rows,
            reason=reason
        )
        return

    if len(valid_df) < min_rows:
        print(
            "Not enough valid ML3 history for training. "
            f"Valid rows: {len(valid_df)} / {min_rows} "
            f"(total history rows: {len(df)})"
        )
        write_status_report(
            status="SKIPPED",
            rows_available=len(valid_df),
            min_rows=min_rows,
            reason="Not enough valid historical rows for model training"
        )
        return

    train_df, holdout_df = split_train_holdout(valid_df)

    X_train_raw = train_df[FEATURE_COLUMNS]
    X_holdout_raw = holdout_df[FEATURE_COLUMNS]
    X_synthetic_raw = create_synthetic_anomalies(X_holdout_raw)

    X_eval_raw = pd.concat([X_holdout_raw, X_synthetic_raw], ignore_index=True)
    y_true = np.array([0] * len(X_holdout_raw) + [1] * len(X_synthetic_raw))

    scaler_eval = StandardScaler()
    X_train_scaled = scaler_eval.fit_transform(X_train_raw)
    X_eval_scaled = scaler_eval.transform(X_eval_raw)

    models = {
        "Isolation Forest": IsolationForest(
            n_estimators=100,
            contamination=0.10,
            random_state=RANDOM_SEED
        ),
        "One-Class SVM": OneClassSVM(
            kernel="rbf",
            nu=0.10,
            gamma="scale"
        )
    }

    synthetic_results = []

    for name, model in models.items():
        print(f"Synthetic labeled evaluation for {name}...")
        synthetic_results.append(
            evaluate_on_synthetic(
                name=name,
                model=model,
                X_train=X_train_scaled,
                X_eval=X_eval_scaled,
                y_true=y_true,
                deployable=True
            )
        )

    lof_model = LocalOutlierFactor(
        n_neighbors=10,
        contamination=0.10
    )
    lof_in_sample = evaluate_model_in_sample("LOF", lof_model, X_train_scaled)
    synthetic_results.append(
        {
            "model": "LOF",
            "deployment_eligible": False,
            "precision": "",
            "recall": "",
            "f1": "",
            "false_positive_rate": "",
            "tn": "",
            "fp": "",
            "fn": "",
            "tp": "",
            "pr_auc": "",
            "execution_time_seconds": lof_in_sample["execution_time_seconds"],
            "normal_examples": int((y_true == 0).sum()),
            "synthetic_anomalies": int((y_true == 1).sum()),
            "seed": RANDOM_SEED,
            "exploratory_only": True,
            "selection_rank": "",
            "reason": "Exploratory only: configured with novelty=False and cannot safely score unseen rows in deployed runtime.",
            "normal_count": lof_in_sample["normal_count"],
            "anomaly_count": lof_in_sample["anomaly_count"],
            "anomaly_rate": lof_in_sample["anomaly_rate"],
            "score_min": lof_in_sample["score_min"],
            "score_max": lof_in_sample["score_max"]
        }
    )

    synthetic_df = pd.DataFrame(synthetic_results)
    ranked = select_model(synthetic_df)

    if ranked is None:
        write_status_report(
            status="FAILED",
            rows_available=len(df),
            min_rows=min_rows,
            reason="No deployable ML3 model available after evaluation"
        )
        print("No deployable ML3 model available after evaluation.")
        return

    best_model_name = ranked.iloc[0]["model"]
    rank_map = {
        row["model"]: int(row["selection_rank"])
        for _, row in ranked.iterrows()
    }
    synthetic_df["selection_rank"] = synthetic_df["model"].map(rank_map).fillna("")

    synthetic_df.to_csv(SYNTHETIC_EVALUATION_REPORT, index=False)

    comparison_rows = synthetic_df.copy()
    comparison_rows.insert(0, "status", "TRAINED")
    comparison_rows.insert(1, "rows_available", len(valid_df))
    comparison_rows.insert(2, "min_rows_required", min_rows)
    comparison_rows.to_csv(COMPARISON_REPORT, index=False)

    final_models = {
        "Isolation Forest": IsolationForest(
            n_estimators=100,
            contamination=0.10,
            random_state=RANDOM_SEED
        ),
        "One-Class SVM": OneClassSVM(
            kernel="rbf",
            nu=0.10,
            gamma="scale"
        )
    }

    final_model = final_models[best_model_name]

    scaler = StandardScaler()
    X_full_scaled = scaler.fit_transform(valid_df[FEATURE_COLUMNS])
    final_model.fit(X_full_scaled)

    joblib.dump(final_model, MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)

    generation_timestamp = pd.Timestamp.now(tz="UTC").isoformat()

    if "timestamp" in valid_df.columns:
        history_timestamp_min = int(valid_df["timestamp"].min())
        history_timestamp_max = int(valid_df["timestamp"].max())
    else:
        history_timestamp_min = None
        history_timestamp_max = None

    selected_metrics_row = synthetic_df[synthetic_df["model"] == best_model_name].iloc[0]

    metadata = {
        "selected_model": best_model_name,
        "selection_policy": [
            "anomaly_f1_desc",
            "anomaly_recall_desc",
            "false_positive_rate_asc",
            "execution_time_seconds_asc"
        ],
        "selection_metrics": {
            "precision": selected_metrics_row["precision"],
            "recall": selected_metrics_row["recall"],
            "f1": selected_metrics_row["f1"],
            "false_positive_rate": selected_metrics_row["false_positive_rate"],
            "pr_auc": selected_metrics_row["pr_auc"],
            "execution_time_seconds": selected_metrics_row["execution_time_seconds"]
        },
        "model_hyperparameters": {
            "Isolation Forest": final_models["Isolation Forest"].get_params(),
            "One-Class SVM": final_models["One-Class SVM"].get_params(),
            "LOF": LocalOutlierFactor(
                n_neighbors=10,
                contamination=0.10
            ).get_params()
        },
        "model_path": str(MODEL_PATH),
        "scaler_path": str(SCALER_PATH),
        "feature_columns": FEATURE_COLUMNS,
        "training_row_count": int(len(valid_df)),
        "total_history_rows": total_history_rows,
        "valid_training_rows": valid_training_rows,
        "excluded_history_rows": excluded_history_rows,
        "exclusion_reasons": {
            key: value
            for key, value in exclusion_reasons.items()
            if key not in {"TOTAL_ROWS", "VALID_ROWS", "EXCLUDED_ROWS"}
        },
        "minimum_required_rows": min_rows,
        "history_timestamp_range": {
            "min": history_timestamp_min,
            "max": history_timestamp_max
        },
        "training_data_hash": hash_training_data(valid_df),
        "random_seed": RANDOM_SEED,
        "minimum_rows": min_rows,
        "training_timestamp": generation_timestamp,
        "synthetic_anomaly_generation_method": {
            "name": "deterministic_perturbation",
            "seed": RANDOM_SEED,
            "recipe": PERTURBATION_RECIPE
        },
        "python_version": platform.python_version(),
        "pandas_version": pd.__version__,
        "scikit_learn_version": sklearn.__version__,
        "joblib_version": joblib.__version__,
        "generation_timestamp": generation_timestamp,
        "evaluation_artifacts": {
            "comparison_report": str(COMPARISON_REPORT),
            "synthetic_evaluation_csv": str(SYNTHETIC_EVALUATION_REPORT),
            "synthetic_evaluation_summary_json": str(SYNTHETIC_EVALUATION_SUMMARY)
        },
        "model_version": generation_timestamp
    }

    with open(METADATA_PATH, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=4)

    with open(SYNTHETIC_EVALUATION_SUMMARY, "w", encoding="utf-8") as f:
        json.dump(
            {
                "status": "TRAINED",
                "seed": RANDOM_SEED,
                "normal_examples": int((y_true == 0).sum()),
                "synthetic_anomalies": int((y_true == 1).sum()),
                "selected_model": best_model_name,
                "selection_policy": metadata["selection_policy"],
                "selection_metrics": metadata["selection_metrics"],
                "perturbation_recipe": PERTURBATION_RECIPE
            },
            f,
            indent=4
        )

    print("\nML3 anomaly model training completed.")
    print(f"Training rows (valid): {len(valid_df)}")
    print(f"History rows (total): {len(df)}")
    print(f"Excluded rows: {excluded_history_rows}")
    print(f"Minimum rows required: {min_rows}")
    print(f"Selected model: {best_model_name}")
    print(f"Model saved to: {MODEL_PATH}")
    print(f"Scaler saved to: {SCALER_PATH}")
    print(f"Comparison report saved to: {COMPARISON_REPORT}")
    print(f"Synthetic evaluation report saved to: {SYNTHETIC_EVALUATION_REPORT}")


if __name__ == "__main__":
    main()