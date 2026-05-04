import os
import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, f1_score
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.svm import LinearSVC
from sklearn.ensemble import RandomForestClassifier
from sklearn.neural_network import MLPClassifier

DATA_FILE = "data/processed/aw4c_alert_dataset.csv"
MODEL_OUTPUT = "models/alert_priority_model.pkl"
RESULTS_OUTPUT = "reports/model_comparison.csv"


def load_data():
    df = pd.read_csv(DATA_FILE)

    df["message"] = df["message"].fillna("")
    df["alert_id"] = df["alert_id"].fillna("")
    df["severity"] = df["severity"].fillna("")
    df["cwe"] = df["cwe"].fillna(0).astype(str)

    features = [
        "severity_score",
        "has_cwe",
        "is_null_pointer",
        "is_buffer_issue",
        "is_memory_issue",
        "is_obsolete_function",
        "is_cppcheck",
        "alert_id",
        "severity",
        "cwe",
        "message",
    ]

    X = df[features]
    y = df["label"]

    return X, y


def build_preprocessor():
    numeric_features = [
        "severity_score",
        "has_cwe",
        "is_null_pointer",
        "is_buffer_issue",
        "is_memory_issue",
        "is_obsolete_function",
        "is_cppcheck",
    ]

    categorical_features = [
        "alert_id",
        "severity",
        "cwe",
    ]

    preprocessor = ColumnTransformer(
        transformers=[
            ("num", StandardScaler(), numeric_features),
            ("cat", OneHotEncoder(handle_unknown="ignore"), categorical_features),
            ("msg", TfidfVectorizer(max_features=3000, ngram_range=(1, 2)), "message"),
        ]
    )

    return preprocessor


def train_models(X_train, y_train, X_test, y_test):
    preprocessor = build_preprocessor()

    models = {
        "LogisticRegression": LogisticRegression(
            max_iter=2000,
            class_weight="balanced"
        ),
        "SVM": LinearSVC(
            class_weight="balanced"
        ),
        "RandomForest": RandomForestClassifier(
            n_estimators=200,
            class_weight="balanced",
            random_state=42
        ),
        "ANN": MLPClassifier(
            hidden_layer_sizes=(128, 64),
            max_iter=500,
            random_state=42
        )
    }

    results = []
    best_pipeline = None
    best_score = 0
    best_name = ""

    for name, model in models.items():
        print(f"\nTraining {name}...")

        pipeline = Pipeline(
            steps=[
                ("preprocessor", preprocessor),
                ("classifier", model)
            ]
        )

        pipeline.fit(X_train, y_train)
        y_pred = pipeline.predict(X_test)

        acc = accuracy_score(y_test, y_pred)
        weighted_f1 = f1_score(y_test, y_pred, average="weighted")
        macro_f1 = f1_score(y_test, y_pred, average="macro")

        print(f"{name} Accuracy: {acc:.4f}")
        print(f"{name} Weighted F1: {weighted_f1:.4f}")
        print(f"{name} Macro F1: {macro_f1:.4f}")
        print(classification_report(y_test, y_pred))

        results.append({
            "Model": name,
            "Accuracy": acc,
            "Weighted_F1": weighted_f1,
            "Macro_F1": macro_f1
        })

        if weighted_f1 > best_score:
            best_score = weighted_f1
            best_pipeline = pipeline
            best_name = name

    print(f"\nBest model selected: {best_name}")
    return best_pipeline, results


def save_model(model):
    os.makedirs("models", exist_ok=True)
    joblib.dump(model, MODEL_OUTPUT)
    print(f"\nBest model saved to {MODEL_OUTPUT}")


def save_results(results):
    os.makedirs("reports", exist_ok=True)
    df = pd.DataFrame(results)
    df.to_csv(RESULTS_OUTPUT, index=False)
    print(f"\nModel comparison saved to {RESULTS_OUTPUT}")


def main():
    print("Loading dataset...")
    X, y = load_data()

    print("Splitting dataset...")
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y
    )

    best_model, results = train_models(X_train, y_train, X_test, y_test)

    save_model(best_model)
    save_results(results)


if __name__ == "__main__":
    main()