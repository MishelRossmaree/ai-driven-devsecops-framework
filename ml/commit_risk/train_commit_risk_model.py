import json
import joblib
import pandas as pd
import time
from pathlib import Path
import numpy as np

from sklearn.linear_model import LogisticRegression
from sklearn.svm import LinearSVC
from sklearn.ensemble import RandomForestClassifier
from sklearn.neural_network import MLPClassifier

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    classification_report,
    confusion_matrix
)


FEATURE_DIR = Path("data/features/commit_risk")
MODEL_DIR = Path("models/commit_risk")
REPORT_DIR = Path("reports/commit_risk")

MODEL_DIR.mkdir(parents=True, exist_ok=True)
REPORT_DIR.mkdir(parents=True, exist_ok=True)


def load_features():
    X_train = joblib.load(FEATURE_DIR / "X_train.pkl")
    X_valid = joblib.load(FEATURE_DIR / "X_valid.pkl")
    X_test = joblib.load(FEATURE_DIR / "X_test.pkl")

    y_train = joblib.load(FEATURE_DIR / "y_train.pkl")
    y_valid = joblib.load(FEATURE_DIR / "y_valid.pkl")
    y_test = joblib.load(FEATURE_DIR / "y_test.pkl")

    return X_train, X_valid, X_test, y_train, y_valid, y_test


def positive_scores(model, X):
    if hasattr(model, "predict_proba"):
        return model.predict_proba(X)[:, 1]

    if hasattr(model, "decision_function"):
        raw = model.decision_function(X)
        return 1 / (1 + np.exp(-raw))

    return model.predict(X).astype(float)


def evaluate_model(model_name, model, X, y):
    start_inference = time.perf_counter()
    y_pred = model.predict(X)
    inference_time = time.perf_counter() - start_inference

    scores = positive_scores(model, X)

    try:
        roc_auc = roc_auc_score(y, scores)
    except Exception:
        roc_auc = 0.0

    results = {
        "model": model_name,
        "accuracy": accuracy_score(y, y_pred),
        "precision": precision_score(y, y_pred, zero_division=0),
        "recall": recall_score(y, y_pred, zero_division=0),
        "f1_score": f1_score(y, y_pred, zero_division=0),
        "roc_auc": roc_auc,
        "inference_time": inference_time
    }

    print(f"\n===== {model_name} Evaluation =====")
    print("Confusion Matrix:")
    print(confusion_matrix(y, y_pred))
    print("\nClassification Report:")
    print(classification_report(y, y_pred, zero_division=0))

    return results


def main():
    X_train, X_valid, X_test, y_train, y_valid, y_test = load_features()

    models = {
        "Logistic Regression": LogisticRegression(
            max_iter=1000,
            class_weight="balanced"
        ),

        "SVM": LinearSVC(
            class_weight="balanced",
            max_iter=5000
        ),

        "Random Forest": RandomForestClassifier(
            n_estimators=100,
            class_weight="balanced",
            random_state=42,
            n_jobs=-1
        ),

        "ANN": MLPClassifier(
            hidden_layer_sizes=(64,),
            max_iter=20,
            random_state=42
        )
    }

    validation_results = []
    trained_models = {}

    for model_name, model in models.items():
        print(f"\nTraining {model_name}...")
        start_train = time.perf_counter()
        model.fit(X_train, y_train)
        training_time = time.perf_counter() - start_train

        trained_models[model_name] = model

        result = evaluate_model(model_name, model, X_valid, y_valid)
        result["training_time"] = training_time
        result["selected"] = False
        validation_results.append(result)

    results_df = pd.DataFrame(validation_results)
    results_df.to_csv(REPORT_DIR / "validation_model_comparison.csv", index=False)

    best_model_name = results_df.sort_values(
        by="recall",
        ascending=False
    ).iloc[0]["model"]

    results_df["selected"] = results_df["model"].eq(best_model_name)
    results_df.to_csv(REPORT_DIR / "validation_model_comparison.csv", index=False)

    best_model = trained_models[best_model_name]

    print(f"\nBest model based on validation recall: {best_model_name}")

    print("\n===== Final Test Evaluation =====")
    test_result = evaluate_model(best_model_name, best_model, X_test, y_test)
    test_result["training_time"] = float(
        results_df.loc[
            results_df["model"] == best_model_name,
            "training_time"
        ].iloc[0]
    )
    test_result["selected"] = True

    pd.DataFrame([test_result]).to_csv(
        REPORT_DIR / "test_evaluation.csv",
        index=False
    )

    joblib.dump(best_model, MODEL_DIR / "commit_risk_model.pkl")

    metadata = {
        "model_name": best_model_name,
        "dataset": "PRIMEVUL",
        "input_level": "function-level",
        "feature_type": "TF-IDF",
        "selected_reason": "Selected based on validation recall and CI/CD suitability"
    }

    with (MODEL_DIR / "model_metadata.json").open("w", encoding="utf-8") as meta_file:
        json.dump(metadata, meta_file, indent=2)

    print("\nCommit risk model training completed successfully")
    print(f"Best model saved to: {MODEL_DIR / 'commit_risk_model.pkl'}")
    print(f"Model metadata saved to: {MODEL_DIR / 'model_metadata.json'}")
    print(f"Validation comparison saved to: {REPORT_DIR / 'validation_model_comparison.csv'}")
    print(f"Test evaluation saved to: {REPORT_DIR / 'test_evaluation.csv'}")


if __name__ == "__main__":
    main()