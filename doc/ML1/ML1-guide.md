# ML1 Guide

This guide explains what to run, in what order, and how to validate ML1 end-to-end.

## What ML1 Does

ML1 predicts risk for changed C/C++ functions in a commit or pull request and produces:

- function-level report
- commit-level summary report

## Prerequisites

- Python 3 available
- Dependencies installed: `pandas`, `scikit-learn`, `joblib`, `numpy`
- PRIMEVUL raw files present:
  - `data/raw/commit_risk/primevul_train.jsonl`
  - `data/raw/commit_risk/primevul_valid.jsonl`
  - `data/raw/commit_risk/primevul_test.jsonl`

## Training Pipeline (Offline)

Run these scripts in order from repository root.

### Step 1: Convert PRIMEVUL JSONL to CSV

```bash
python3 ml/commit_risk/primevul_to_dataset.py
```

Expected outputs:

- `data/processed/commit_risk/train.csv`
- `data/processed/commit_risk/valid.csv`
- `data/processed/commit_risk/test.csv`

### Step 2: Build TF-IDF Features

```bash
python3 ml/commit_risk/prepare_commit_features.py
```

Expected outputs:

- `data/features/commit_risk/tfidf_vectorizer.pkl`
- `data/features/commit_risk/X_train.pkl`
- `data/features/commit_risk/X_valid.pkl`
- `data/features/commit_risk/X_test.pkl`
- `data/features/commit_risk/y_train.pkl`
- `data/features/commit_risk/y_valid.pkl`
- `data/features/commit_risk/y_test.pkl`

### Step 3: Train and Select Model

```bash
python3 ml/commit_risk/train_commit_risk_model.py
```

Expected outputs:

- `models/commit_risk/commit_risk_model.pkl`
- `models/commit_risk/model_metadata.json`
- `reports/commit_risk/validation_model_comparison.csv`
- `reports/commit_risk/test_evaluation.csv`

Selection logic:

- Trains Logistic Regression, SVM, Random Forest, ANN
- Selects best model by highest validation recall
- Writes model comparison evidence including timing and AUC

## Runtime Inference (Local CLI)

Run ML1 predictor on current repo changes.

```bash
python3 ml/commit_risk/commit_risk_predictor.py \
  --scan-path "." \
  --model-path "models/commit_risk/commit_risk_model.pkl" \
  --vectorizer-path "data/features/commit_risk/tfidf_vectorizer.pkl" \
  --high-threshold "70" \
  --medium-threshold "40" \
  --review-confidence-threshold "0.2" \
  --output "reports/commit_risk/commit_risk_report.csv" \
  --summary-output "reports/commit_risk/commit_risk_summary.csv"
```

Optional metadata args for non-GitHub local runs:

- `--commit-sha`
- `--branch`
- `--event-type`
- `--author`
- `--base-ref`
- `--head-ref`

## Runtime Inference in GitHub Actions

Use the framework action in target repo workflow:

```yaml
- name: Run AI DevSecOps Framework
  uses: MishelRossmaree/ai-driven-devsecops-framework@main
  with:
    scan-path: "."
    ml1-high-threshold: "70"
    ml1-medium-threshold: "40"
    ml1-review-confidence-threshold: "0.2"
```

Important checkout setting:

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0
```

## ML1 Input Parameters

Action-level inputs (from `action.yml`):

- `scan-path`
- `ml1-high-threshold`
- `ml1-medium-threshold`
- `ml1-review-confidence-threshold`

Predictor-level core args:

- `--model-path`
- `--vectorizer-path`
- `--output`
- `--summary-output`

## How to Read ML1 Output

### commit_risk_report.csv

Each row represents one analyzed function (or fallback file record):

- `risk_score`: 0 to 100
- `risk_level`: HIGH, REVIEW_REQUIRED, MEDIUM, LOW
- `confidence`: model confidence derived from probability distance to 0.5
- `top_risky_terms`: matched high-risk lexical indicators
- `risk_reason`: explanation text

### commit_risk_summary.csv

Single-row summary per run:

- changed file/function counts
- counts by risk category
- max score
- final `commit_risk_level`
- runtime metrics

## Decision Semantics

Function-level to commit-level precedence:

1. HIGH
2. REVIEW_REQUIRED
3. MEDIUM
4. LOW
5. SKIPPED

Interpretation:

- Any HIGH function elevates commit to HIGH.
- If no HIGH but at least one low-confidence function, commit is REVIEW_REQUIRED.

## Validation Checklist

1. Run safe C/C++ change and confirm LOW or PASS-oriented output.
2. Run known vulnerable pattern change and confirm HIGH appears.
3. Run ambiguous change and check REVIEW_REQUIRED behavior.
4. Confirm reports are produced even when no C/C++ changes (SKIPPED summary).

## Common Issues and Fixes

### ML1 says no C/C++ changes detected

- Check trigger path filters.
- Check `scan-path`.
- Ensure git history is available (`fetch-depth: 0`).

### Predictor fails with threshold error

- Ensure medium threshold is less than high threshold.
- Ensure review confidence threshold is within [0, 1].

### No model/vectorizer found

- Run training pipeline steps first.
- Verify paths in predictor arguments.

### PR behavior differs from push behavior

- PR uses base/head refs.
- Push often uses HEAD~1...HEAD fallback.
- Ensure sufficient git history exists on runner.

## Suggested Operational Defaults

- `ml1-high-threshold`: 70
- `ml1-medium-threshold`: 40
- `ml1-review-confidence-threshold`: 0.2

Tune these using your validation results and false positive tolerance.

## Related Documents

- [doc/ML1/ML1-OVERVIEW.md](doc/ML1/ML1-OVERVIEW.md)
- [doc/Github/OVERVIEW.md](doc/Github/OVERVIEW.md)
- [doc/Github/Github.md](doc/Github/Github.md)
