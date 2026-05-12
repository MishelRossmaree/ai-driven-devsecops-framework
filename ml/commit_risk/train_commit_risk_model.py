import joblib
import pandas as pd
from pathlib import Path

from sklearn.linear_model import LogisticRegression
from sklearn.svm import LinearSVC
from sklearn.ensemble import RandomForestClassifier
from sklearn.neural_network import MLPClassifier

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
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


def evaluate_model(model_name, model, X, y):
    y_pred = model.predict(X)

    results = {
        "model": model_name,
        "accuracy": accuracy_score(y, y_pred),
        "precision": precision_score(y, y_pred, zero_division=0),
        "recall": recall_score(y, y_pred, zero_division=0),
        "f1_score": f1_score(y, y_pred, zero_division=0),
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
        model.fit(X_train, y_train)

        trained_models[model_name] = model

        result = evaluate_model(model_name, model, X_valid, y_valid)
        validation_results.append(result)

    results_df = pd.DataFrame(validation_results)
    results_df.to_csv(REPORT_DIR / "validation_model_comparison.csv", index=False)

    best_model_name = results_df.sort_values(
        by="recall",
        ascending=False
    ).iloc[0]["model"]

    best_model = trained_models[best_model_name]

    print(f"\nBest model based on validation recall: {best_model_name}")

    print("\n===== Final Test Evaluation =====")
    test_result = evaluate_model(best_model_name, best_model, X_test, y_test)

    pd.DataFrame([test_result]).to_csv(
        REPORT_DIR / "test_evaluation.csv",
        index=False
    )

    joblib.dump(best_model, MODEL_DIR / "commit_risk_model.pkl")

    print("\nCommit risk model training completed successfully")
    print(f"Best model saved to: {MODEL_DIR / 'commit_risk_model.pkl'}")
    print(f"Validation comparison saved to: {REPORT_DIR / 'validation_model_comparison.csv'}")
    print(f"Test evaluation saved to: {REPORT_DIR / 'test_evaluation.csv'}")


if __name__ == "__main__":
    main()