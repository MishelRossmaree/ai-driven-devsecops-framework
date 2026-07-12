import json
import os
from pathlib import Path

import joblib
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix, precision_recall_fscore_support, f1_score
from sklearn.model_selection import GroupShuffleSplit
from sklearn.neural_network import MLPClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.svm import LinearSVC

DATA_FILE = Path("data/processed/alert_prioritizer/clang/clang_alert_features.csv")
MODEL_OUTPUT = Path("models/alert_prioritizer/clang/clang_priority_model.pkl")
METADATA_OUTPUT = Path("models/alert_prioritizer/clang/model_metadata.json")
VALIDATION_RESULTS_OUTPUT = Path("reports/alert_prioritizer/clang/validation_model_comparison.csv")
TEST_RESULTS_OUTPUT = Path("reports/alert_prioritizer/clang/test_evaluation.csv")

DEDUP_KEY = [
    "juliet_case_id",
    "source_file",
    "line",
    "alert_id",
    "severity",
    "message",
    "label",
]
GROUPING_KEY = "juliet_case_id"
SPLIT_SEED = 42
LABEL_SET = [0, 1, 2]

EXCLUDED_LEAKAGE_FIELDS = [
    "annotation_id",
    "source_file",
    "line",
    "juliet_case_id",
    "juliet_cwe_family",
    "ground_truth_status",
    "is_bad_path",
    "is_good_path",
    "raw_report_path",
    "manual_priority",
    "annotation_reason",
    "priority",
    "label",
    "cwe",
]

MODEL_FEATURE_COLUMNS = [
    "severity_score",
    "has_cwe",
    "is_null_pointer",
    "is_buffer_issue",
    "is_memory_issue",
    "is_obsolete_function",
    "is_clang",
    "alert_id",
    "severity",
    "message",
]


def ensure_directories():
    MODEL_OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    METADATA_OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    VALIDATION_RESULTS_OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    TEST_RESULTS_OUTPUT.parent.mkdir(parents=True, exist_ok=True)


def load_and_prepare_data():
    df = pd.read_csv(DATA_FILE)
    if df.empty:
        raise ValueError(f"Feature dataset is empty: {DATA_FILE}")

    for column in DEDUP_KEY + [GROUPING_KEY, "priority", "label"] + MODEL_FEATURE_COLUMNS:
        if column not in df.columns:
            raise ValueError(f"Required column missing from dataset: {column}")

    df["message"] = df["message"].fillna("")
    df["alert_id"] = df["alert_id"].fillna("")
    df["severity"] = df["severity"].fillna("")

    total_rows = len(df)
    unknown_mask = ~df["label"].isin(LABEL_SET)
    excluded_unknown_count = int(unknown_mask.sum())
    model_df = df.loc[~unknown_mask].copy()

    if model_df.empty:
        raise ValueError("No labeled rows available for model training after excluding unknown priority rows.")

    model_df["label"] = model_df["label"].astype(int)
    before_dedup_rows = len(model_df)
    model_df = model_df.drop_duplicates(subset=DEDUP_KEY, keep="first")
    after_dedup_rows = len(model_df)

    return {
        "full_df": df,
        "model_df": model_df,
        "total_rows": total_rows,
        "excluded_unknown_count": excluded_unknown_count,
        "before_dedup_rows": before_dedup_rows,
        "after_dedup_rows": after_dedup_rows,
    }


def class_distribution(series):
    counts = series.value_counts().to_dict()
    return {str(label): int(counts.get(label, 0)) for label in LABEL_SET}


def split_with_group_constraints(df, max_attempts=500):
    groups = df[GROUPING_KEY].astype(str)
    labels = df["label"].astype(int)

    for attempt in range(max_attempts):
        seed = SPLIT_SEED + attempt

        outer_splitter = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=seed)
        train_val_idx, test_idx = next(outer_splitter.split(df, labels, groups))

        train_val_df = df.iloc[train_val_idx].copy()
        test_df = df.iloc[test_idx].copy()

        inner_groups = train_val_df[GROUPING_KEY].astype(str)
        inner_labels = train_val_df["label"].astype(int)
        inner_splitter = GroupShuffleSplit(n_splits=1, test_size=0.25, random_state=seed)
        train_idx, val_idx = next(inner_splitter.split(train_val_df, inner_labels, inner_groups))

        train_df = train_val_df.iloc[train_idx].copy()
        val_df = train_val_df.iloc[val_idx].copy()

        split_sets = {
            "train": train_df,
            "validation": val_df,
            "test": test_df,
        }

        has_all_classes = all(set(LABEL_SET).issubset(set(split_df["label"].unique())) for split_df in split_sets.values())
        if not has_all_classes:
            continue

        train_groups = set(train_df[GROUPING_KEY].astype(str))
        val_groups = set(val_df[GROUPING_KEY].astype(str))
        test_groups = set(test_df[GROUPING_KEY].astype(str))
        no_group_overlap = not (train_groups & val_groups or train_groups & test_groups or val_groups & test_groups)
        if not no_group_overlap:
            continue

        def signature_set(split_df):
            return set(tuple(split_df[column].astype(str).tolist()[row] for column in DEDUP_KEY) for row in range(len(split_df)))

        train_signatures = signature_set(train_df)
        val_signatures = signature_set(val_df)
        test_signatures = signature_set(test_df)
        no_exact_overlap = not (
            train_signatures & val_signatures
            or train_signatures & test_signatures
            or val_signatures & test_signatures
        )
        if not no_exact_overlap:
            continue

        return split_sets, {
            "attempt": attempt,
            "seed": seed,
            "no_group_overlap": no_group_overlap,
            "no_exact_overlap": no_exact_overlap,
            "train_val_group_overlap": int(len(train_groups & val_groups)),
            "train_test_group_overlap": int(len(train_groups & test_groups)),
            "val_test_group_overlap": int(len(val_groups & test_groups)),
            "train_val_exact_overlap": int(len(train_signatures & val_signatures)),
            "train_test_exact_overlap": int(len(train_signatures & test_signatures)),
            "val_test_exact_overlap": int(len(val_signatures & test_signatures)),
        }

    raise ValueError(
        "Unable to create a reliable 3-class grouped split with no leakage and class coverage in train/validation/test."
    )


def build_preprocessor():
    numeric_features = [
        "severity_score",
        "has_cwe",
        "is_null_pointer",
        "is_buffer_issue",
        "is_memory_issue",
        "is_obsolete_function",
        "is_clang",
    ]
    categorical_features = ["alert_id", "severity"]

    return ColumnTransformer(
        transformers=[
            ("num", StandardScaler(), numeric_features),
            ("cat", OneHotEncoder(handle_unknown="ignore"), categorical_features),
            ("msg", TfidfVectorizer(max_features=3000, ngram_range=(1, 2)), "message"),
        ]
    )


def evaluate_predictions(y_true, y_pred):
    metrics = {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "macro_f1": float(f1_score(y_true, y_pred, average="macro", zero_division=0)),
        "weighted_f1": float(f1_score(y_true, y_pred, average="weighted", zero_division=0)),
    }

    precision, recall, f1, support = precision_recall_fscore_support(
        y_true,
        y_pred,
        labels=LABEL_SET,
        zero_division=0,
    )
    confusion = confusion_matrix(y_true, y_pred, labels=LABEL_SET)

    metrics["high_recall"] = float(recall[2])
    metrics["confusion_matrix"] = json.dumps(confusion.tolist())

    for index, label in enumerate(LABEL_SET):
        metrics[f"class_{label}_precision"] = float(precision[index])
        metrics[f"class_{label}_recall"] = float(recall[index])
        metrics[f"class_{label}_f1"] = float(f1[index])
        metrics[f"class_{label}_support"] = int(support[index])

    return metrics


def train_and_select_model(train_df, validation_df):
    preprocessor = build_preprocessor()

    candidates = {
        "Logistic Regression": LogisticRegression(max_iter=2000, class_weight="balanced", random_state=SPLIT_SEED),
        "SVM": LinearSVC(class_weight="balanced", random_state=SPLIT_SEED),
        "Random Forest": RandomForestClassifier(
            n_estimators=300,
            class_weight="balanced",
            random_state=SPLIT_SEED,
        ),
        "ANN": MLPClassifier(hidden_layer_sizes=(128, 64), max_iter=500, random_state=SPLIT_SEED),
    }

    validation_rows = []
    best = None

    x_train = train_df[MODEL_FEATURE_COLUMNS]
    y_train = train_df["label"]
    x_val = validation_df[MODEL_FEATURE_COLUMNS]
    y_val = validation_df["label"]

    for model_name, model in candidates.items():
        pipeline = Pipeline(
            steps=[
                ("preprocessor", preprocessor),
                ("classifier", model),
            ]
        )

        pipeline.fit(x_train, y_train)
        val_pred = pipeline.predict(x_val)
        metrics = evaluate_predictions(y_val, val_pred)

        row = {"model": model_name, **metrics}
        validation_rows.append(row)

        selection_key = (
            metrics["macro_f1"],
            metrics["high_recall"],
            metrics["weighted_f1"],
            metrics["accuracy"],
        )

        if best is None or selection_key > best["selection_key"]:
            best = {
                "model_name": model_name,
                "pipeline": pipeline,
                "selection_key": selection_key,
                "validation_metrics": metrics,
                "model_params": model.get_params(),
            }

    validation_df_out = pd.DataFrame(validation_rows)
    validation_df_out.to_csv(VALIDATION_RESULTS_OUTPUT, index=False)

    return best, list(candidates.keys()), validation_df_out


def evaluate_on_test(best_model, test_df):
    x_test = test_df[MODEL_FEATURE_COLUMNS]
    y_test = test_df["label"]
    test_pred = best_model["pipeline"].predict(x_test)
    metrics = evaluate_predictions(y_test, test_pred)

    test_row = {
        "model": best_model["model_name"],
        **metrics,
    }
    pd.DataFrame([test_row]).to_csv(TEST_RESULTS_OUTPUT, index=False)
    return test_row


def split_summary(split_name, split_df):
    return {
        "rows": int(len(split_df)),
        "groups": int(split_df[GROUPING_KEY].astype(str).nunique()),
        "class_distribution": class_distribution(split_df["label"]),
    }


def save_metadata(context, splits, overlap_checks, candidate_models, best_model, test_metrics):
    metadata = {
        "dataset_row_counts": {
            "total_rows": int(context["total_rows"]),
            "known_priority_rows_before_dedup": int(context["before_dedup_rows"]),
            "known_priority_rows_after_dedup": int(context["after_dedup_rows"]),
        },
        "excluded_unknown_count": int(context["excluded_unknown_count"]),
        "class_distributions": {
            "overall_known": class_distribution(context["model_df"]["label"]),
            "train": split_summary("train", splits["train"])["class_distribution"],
            "validation": split_summary("validation", splits["validation"])["class_distribution"],
            "test": split_summary("test", splits["test"])["class_distribution"],
        },
        "deduplication_key": DEDUP_KEY,
        "grouping_key": GROUPING_KEY,
        "split_seed": SPLIT_SEED,
        "split_counts": {
            "train": split_summary("train", splits["train"]),
            "validation": split_summary("validation", splits["validation"]),
            "test": split_summary("test", splits["test"]),
        },
        "overlap_check_results": overlap_checks,
        "feature_columns": MODEL_FEATURE_COLUMNS,
        "excluded_leakage_fields": EXCLUDED_LEAKAGE_FIELDS,
        "candidate_models": candidate_models,
        "selection_metric": "macro_f1 > high_recall > weighted_f1 > accuracy",
        "selected_model": best_model["model_name"],
        "selected_model_parameters": best_model["model_params"],
        "validation_metrics": best_model["validation_metrics"],
        "final_test_metrics": test_metrics,
        "artifact_paths": {
            "model": str(MODEL_OUTPUT),
            "metadata": str(METADATA_OUTPUT),
            "validation_model_comparison": str(VALIDATION_RESULTS_OUTPUT),
            "test_evaluation": str(TEST_RESULTS_OUTPUT),
        },
    }

    with METADATA_OUTPUT.open("w", encoding="utf-8") as handle:
        json.dump(metadata, handle, indent=2)


def main():
    ensure_directories()

    context = load_and_prepare_data()
    model_df = context["model_df"]

    splits, overlap_checks = split_with_group_constraints(model_df)

    best_model, candidate_models, validation_table = train_and_select_model(
        splits["train"],
        splits["validation"],
    )

    test_metrics = evaluate_on_test(best_model, splits["test"])

    joblib.dump(best_model["pipeline"], MODEL_OUTPUT)
    save_metadata(context, splits, overlap_checks, candidate_models, best_model, test_metrics)

    for split_name in ["train", "validation", "test"]:
        summary = split_summary(split_name, splits[split_name])
        print(f"{split_name} rows: {summary['rows']}")
        print(f"{split_name} groups: {summary['groups']}")
        print(f"{split_name} class distribution: {summary['class_distribution']}")

    print(f"excluded unknown count: {context['excluded_unknown_count']}")
    print(f"overlap check results: {overlap_checks}")
    print(f"selected model: {best_model['model_name']}")
    print("validation model comparison:")
    print(validation_table[["model", "accuracy", "macro_f1", "weighted_f1", "high_recall"]])
    print(f"final test metrics: {test_metrics}")
    print(f"model artifact: {MODEL_OUTPUT}")
    print(f"metadata artifact: {METADATA_OUTPUT}")
    print(f"validation report: {VALIDATION_RESULTS_OUTPUT}")
    print(f"test report: {TEST_RESULTS_OUTPUT}")


if __name__ == "__main__":
    main()
