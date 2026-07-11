import json
import os
from collections import Counter

import joblib
import pandas as pd

from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import (
    classification_report,
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_recall_fscore_support,
)
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.svm import LinearSVC
from sklearn.ensemble import RandomForestClassifier
from sklearn.neural_network import MLPClassifier

DATA_FILE = "data/processed/alert_prioritizer/cppcheck/aw4c_alert_dataset.csv"
MODEL_OUTPUT = "models/alert_prioritizer/cppcheck/alert_priority_model.pkl"
VALIDATION_RESULTS_OUTPUT = "reports/alert_prioritizer/cppcheck/validation_model_comparison.csv"
TEST_EVALUATION_OUTPUT = "reports/alert_prioritizer/cppcheck/test_evaluation.csv"
METADATA_OUTPUT = "models/alert_prioritizer/cppcheck/model_metadata.json"

SEED = 42
TEST_SIZE = 0.2
VALIDATION_SIZE = 0.2
SPLIT_SEARCH_TRIALS = 120
REQUIRED_LABELS = [0, 1, 2]

DUPLICATE_ID_FIELDS = [
    "tool",
    "file",
    "line",
    "alert_id",
    "cwe",
    "severity",
    "message",
    "is_actionable",
    "priority",
    "label",
]


def class_distribution(y):
    counts = Counter(list(y))
    total = sum(counts.values())

    distribution = {}

    for label in REQUIRED_LABELS:
        count = int(counts.get(label, 0))
        pct = float(count / total) if total else 0.0
        distribution[str(label)] = {
            "count": count,
            "percent": round(pct, 6),
        }

    return distribution


def has_all_required_classes(y):
    labels = set(list(y))
    return all(label in labels for label in REQUIRED_LABELS)


def dist_divergence(reference_dist, candidate_dist):
    divergence = 0.0

    for label in REQUIRED_LABELS:
        key = str(label)
        ref_pct = float(reference_dist[key]["percent"])
        cand_pct = float(candidate_dist[key]["percent"])
        divergence += abs(ref_pct - cand_pct)

    return divergence


def build_grouped_split(df, y, seed):
    full_dist = class_distribution(y)
    val_size_within_trainval = VALIDATION_SIZE / (1.0 - TEST_SIZE)

    best = None
    best_score = None

    for offset in range(SPLIT_SEARCH_TRIALS):
        rs = seed + offset

        gss_test = GroupShuffleSplit(
            n_splits=1,
            test_size=TEST_SIZE,
            random_state=rs,
        )

        trainval_idx, test_idx = next(gss_test.split(df, y, groups=df["file"]))

        trainval_df = df.iloc[trainval_idx]
        trainval_y = y.iloc[trainval_idx]

        gss_val = GroupShuffleSplit(
            n_splits=1,
            test_size=val_size_within_trainval,
            random_state=rs + 10_000,
        )

        train_local_idx, valid_local_idx = next(
            gss_val.split(trainval_df, trainval_y, groups=trainval_df["file"])
        )

        train_idx = trainval_idx[train_local_idx]
        valid_idx = trainval_idx[valid_local_idx]

        y_train = y.iloc[train_idx]
        y_valid = y.iloc[valid_idx]
        y_test = y.iloc[test_idx]

        if not (
            has_all_required_classes(y_train)
            and has_all_required_classes(y_valid)
            and has_all_required_classes(y_test)
        ):
            continue

        train_dist = class_distribution(y_train)
        valid_dist = class_distribution(y_valid)
        test_dist = class_distribution(y_test)

        score = (
            dist_divergence(full_dist, train_dist)
            + dist_divergence(full_dist, valid_dist)
            + dist_divergence(full_dist, test_dist)
        )

        if best_score is None or score < best_score:
            best_score = score
            best = {
                "train_idx": train_idx,
                "valid_idx": valid_idx,
                "test_idx": test_idx,
                "train_dist": train_dist,
                "valid_dist": valid_dist,
                "test_dist": test_dist,
            }

    if best is None:
        raise RuntimeError(
            "Could not build grouped splits that contain all required classes. "
            "Review dataset balance or adjust split sizes."
        )

    return best


def assert_no_file_overlap(df_train, df_valid, df_test):
    train_files = set(df_train["file"].astype(str))
    valid_files = set(df_valid["file"].astype(str))
    test_files = set(df_test["file"].astype(str))

    overlap_train_valid = train_files & valid_files
    overlap_train_test = train_files & test_files
    overlap_valid_test = valid_files & test_files

    if overlap_train_valid or overlap_train_test or overlap_valid_test:
        raise RuntimeError("Source-file overlap detected across grouped splits.")

    return {
        "train_valid": 0,
        "train_test": 0,
        "valid_test": 0,
    }


def row_signature_set(df):
    signature = df[DUPLICATE_ID_FIELDS].fillna("__NA__").astype(str)
    return set(map(tuple, signature.to_numpy()))


def assert_no_cross_split_duplicates(df_train, df_valid, df_test):
    train_sig = row_signature_set(df_train)
    valid_sig = row_signature_set(df_valid)
    test_sig = row_signature_set(df_test)

    overlap_train_valid = len(train_sig & valid_sig)
    overlap_train_test = len(train_sig & test_sig)
    overlap_valid_test = len(valid_sig & test_sig)

    if overlap_train_valid or overlap_train_test or overlap_valid_test:
        raise RuntimeError("Exact duplicate rows detected across splits.")

    return {
        "train_valid": overlap_train_valid,
        "train_test": overlap_train_test,
        "valid_test": overlap_valid_test,
    }


def summarize_split(name, df_part, y_part):
    print(f"\n{name} split summary:")
    print(f"Rows: {len(df_part)}")
    print(f"Source file groups: {df_part['file'].nunique()}")
    print("Class distribution:")
    print(pd.Series(y_part).value_counts().sort_index())


def load_data():
    df = pd.read_csv(DATA_FILE)

    before_dedup = len(df)
    df = df.drop_duplicates(subset=DUPLICATE_ID_FIELDS, keep="first").copy()
    after_dedup = len(df)

    print(f"Rows before deduplication: {before_dedup}")
    print(f"Rows after deduplication: {after_dedup}")
    print(f"Duplicate rows removed: {before_dedup - after_dedup}")
    print(f"Deduplication fields: {DUPLICATE_ID_FIELDS}")

    missing_columns = [col for col in DUPLICATE_ID_FIELDS if col not in df.columns]
    if missing_columns:
        raise ValueError(f"Dataset is missing required columns: {missing_columns}")

    df["message"] = df["message"].fillna("")
    df["alert_id"] = df["alert_id"].fillna("")
    df["severity"] = df["severity"].fillna("")
    df["cwe"] = df["cwe"].fillna(0).astype(str)

    if not has_all_required_classes(df["label"]):
        raise ValueError(
            "Dataset does not contain all required priority classes "
            f"{REQUIRED_LABELS}."
        )

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

    return df, X, y, before_dedup, after_dedup


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


def evaluate_predictions(model_name, y_true, y_pred):
    acc = accuracy_score(y_true, y_pred)
    weighted_f1 = f1_score(y_true, y_pred, average="weighted", zero_division=0)
    macro_f1 = f1_score(y_true, y_pred, average="macro", zero_division=0)

    precision, recall, f1, support = precision_recall_fscore_support(
        y_true,
        y_pred,
        labels=REQUIRED_LABELS,
        zero_division=0,
    )

    conf = confusion_matrix(y_true, y_pred, labels=REQUIRED_LABELS)

    print(f"{model_name} Accuracy: {acc:.4f}")
    print(f"{model_name} Weighted F1: {weighted_f1:.4f}")
    print(f"{model_name} Macro F1: {macro_f1:.4f}")
    print(f"{model_name} HIGH-class Recall: {recall[2]:.4f}")
    print(classification_report(y_true, y_pred, labels=REQUIRED_LABELS, zero_division=0))
    print("Confusion Matrix:")
    print(conf)

    return {
        "Model": model_name,
        "Accuracy": acc,
        "Weighted_F1": weighted_f1,
        "Macro_F1": macro_f1,
        "HIGH_Recall": float(recall[2]),
        "Precision_LOW": float(precision[0]),
        "Recall_LOW": float(recall[0]),
        "F1_LOW": float(f1[0]),
        "Support_LOW": int(support[0]),
        "Precision_MEDIUM": float(precision[1]),
        "Recall_MEDIUM": float(recall[1]),
        "F1_MEDIUM": float(f1[1]),
        "Support_MEDIUM": int(support[1]),
        "Precision_HIGH": float(precision[2]),
        "Recall_HIGH": float(recall[2]),
        "F1_HIGH": float(f1[2]),
        "Support_HIGH": int(support[2]),
        "Confusion_Matrix": json.dumps(conf.tolist()),
    }


def train_models(X_train, y_train, X_valid, y_valid):
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
    best_rank = None
    best_name = ""

    for name, model in models.items():
        print(f"\nTraining {name} (train split)...")

        pipeline = Pipeline(
            steps=[
                ("preprocessor", preprocessor),
                ("classifier", model)
            ]
        )

        pipeline.fit(X_train, y_train)
        y_valid_pred = pipeline.predict(X_valid)

        metrics = evaluate_predictions(name, y_valid, y_valid_pred)
        results.append(metrics)

        # Model selection rule:
        # 1) Primary metric: Macro F1 (higher is better)
        # 2) Secondary metric: HIGH-class recall (higher is better)
        # 3) Tertiary tie-breakers: Weighted F1, Accuracy
        rank = (
            metrics["Macro_F1"],
            metrics["HIGH_Recall"],
            metrics["Weighted_F1"],
            metrics["Accuracy"],
        )

        if best_rank is None or rank > best_rank:
            best_rank = rank
            best_pipeline = pipeline
            best_name = name

    print("\nBest model selected using validation metrics")
    print("Primary metric: Macro_F1")
    print("Secondary metric: HIGH_Recall")
    print(f"Selected model: {best_name}")

    return best_pipeline, best_name, results


def evaluate_final_model(model_name, model, X_test, y_test):
    print("\nEvaluating selected model once on untouched test split...")
    y_test_pred = model.predict(X_test)
    return evaluate_predictions(model_name, y_test, y_test_pred)


def save_model(model):
    os.makedirs("models", exist_ok=True)
    joblib.dump(model, MODEL_OUTPUT)
    print(f"\nBest model saved to {MODEL_OUTPUT}")


def save_validation_results(results):
    os.makedirs(os.path.dirname(VALIDATION_RESULTS_OUTPUT), exist_ok=True)
    df = pd.DataFrame(results)
    df.to_csv(VALIDATION_RESULTS_OUTPUT, index=False)
    print(f"\nValidation model comparison saved to {VALIDATION_RESULTS_OUTPUT}")


def save_test_evaluation(result):
    os.makedirs(os.path.dirname(TEST_EVALUATION_OUTPUT), exist_ok=True)
    pd.DataFrame([result]).to_csv(TEST_EVALUATION_OUTPUT, index=False)
    print(f"Final test evaluation saved to {TEST_EVALUATION_OUTPUT}")


def to_jsonable(value):
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, dict):
        return {str(k): to_jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [to_jsonable(v) for v in value]
    return str(value)


def save_metadata(metadata):
    os.makedirs(os.path.dirname(METADATA_OUTPUT), exist_ok=True)

    with open(METADATA_OUTPUT, "w", encoding="utf-8") as f:
        json.dump(to_jsonable(metadata), f, indent=2)

    print(f"Model metadata saved to {METADATA_OUTPUT}")


def main():
    print("Loading dataset...")
    df, X, y, before_dedup, after_dedup = load_data()

    print("\nCreating grouped train/validation/test split by source file...")
    split = build_grouped_split(df, y, SEED)

    train_idx = split["train_idx"]
    valid_idx = split["valid_idx"]
    test_idx = split["test_idx"]

    df_train = df.iloc[train_idx].copy()
    df_valid = df.iloc[valid_idx].copy()
    df_test = df.iloc[test_idx].copy()

    X_train = X.iloc[train_idx]
    y_train = y.iloc[train_idx]
    X_valid = X.iloc[valid_idx]
    y_valid = y.iloc[valid_idx]
    X_test = X.iloc[test_idx]
    y_test = y.iloc[test_idx]

    summarize_split("Train", df_train, y_train)
    summarize_split("Validation", df_valid, y_valid)
    summarize_split("Test", df_test, y_test)

    file_overlap = assert_no_file_overlap(df_train, df_valid, df_test)
    row_overlap = assert_no_cross_split_duplicates(df_train, df_valid, df_test)

    if not (
        has_all_required_classes(y_train)
        and has_all_required_classes(y_valid)
        and has_all_required_classes(y_test)
    ):
        raise RuntimeError("One or more splits are missing required priority classes.")

    print("\nSplit integrity checks passed:")
    print(f"No source-file overlap across splits: {file_overlap}")
    print(f"No exact duplicate rows across splits: {row_overlap}")
    print(f"Required classes present in each split: {REQUIRED_LABELS}")

    best_model, selected_model_name, validation_results = train_models(
        X_train,
        y_train,
        X_valid,
        y_valid,
    )

    test_result = evaluate_final_model(selected_model_name, best_model, X_test, y_test)
    test_result["Selected"] = True

    save_model(best_model)
    save_validation_results(validation_results)
    save_test_evaluation(test_result)

    selected_classifier = best_model.named_steps["classifier"]

    metadata = {
        "dataset": {
            "source_file": DATA_FILE,
            "before_dedup_rows": before_dedup,
            "after_dedup_rows": after_dedup,
            "deduplication_fields": DUPLICATE_ID_FIELDS,
            "full_class_distribution": class_distribution(y),
        },
        "split_strategy": {
            "name": "grouped_by_source_file_with_distribution_search",
            "seed": SEED,
            "search_trials": SPLIT_SEARCH_TRIALS,
            "test_size": TEST_SIZE,
            "validation_size": VALIDATION_SIZE,
            "required_classes": REQUIRED_LABELS,
            "train_rows": int(len(df_train)),
            "validation_rows": int(len(df_valid)),
            "test_rows": int(len(df_test)),
            "train_group_count": int(df_train["file"].nunique()),
            "validation_group_count": int(df_valid["file"].nunique()),
            "test_group_count": int(df_test["file"].nunique()),
            "train_class_distribution": class_distribution(y_train),
            "validation_class_distribution": class_distribution(y_valid),
            "test_class_distribution": class_distribution(y_test),
            "overlap_checks": {
                "source_file_overlap": file_overlap,
                "cross_split_duplicate_rows": row_overlap,
            },
        },
        "selection": {
            "primary_metric": "Macro_F1",
            "secondary_metric": "HIGH_Recall",
            "reported_secondary_metrics": ["Weighted_F1", "Accuracy"],
            "selected_model": selected_model_name,
            "selected_model_parameters": selected_classifier.get_params(),
        },
        "artifacts": {
            "model_path": MODEL_OUTPUT,
            "validation_results_path": VALIDATION_RESULTS_OUTPUT,
            "test_evaluation_path": TEST_EVALUATION_OUTPUT,
        },
    }

    save_metadata(metadata)


if __name__ == "__main__":
    main()