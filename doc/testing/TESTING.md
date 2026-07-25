# Automated Testing

## Testing Strategy

The automated test suite employs different testing levels for different purposes:

- **Unit Testing**: Tests individual functions and components in isolation using mocked dependencies. Validates deterministic logic, error handling, and data transformations without external dependencies.
- **Integration Testing** (planned): Tests component interaction and model loading with real trained models in controlled environments.
- **Functional Testing** (separate repository): Tests complete GitHub Actions workflows end-to-end with real scanner execution.
- **ML Model Evaluation**: Separate from software testing; uses validation and test datasets to measure precision, recall, F1-score, and other performance metrics stored in `reports/`.

Unit-test code coverage demonstrates that decision logic branches and error paths have been exercised. It does not measure ML model prediction quality, which is documented in model evaluation artefacts.

## Testing Tools

The test suite uses:

- **pytest**: Test execution, collection, and assertion framework.
- **pytest-cov**: Code coverage measurement and reporting.
- **pandas**: DataFrame construction and assertions.
- **numpy**: Numerical array operations for model score testing.
- **monkeypatch** (pytest fixture): Mocks subprocess calls, Git commands, environment variables, and module functions.
- **tmp_path** (pytest fixture): Provides isolated temporary directories for file I/O.
- **capsys** (pytest fixture): Captures and verifies console output.
- **Mock** (unittest.mock): Creates fake model objects and dependencies.

## Test Structure

The current test structure after Phase 2:

```
tests/
├── conftest.py
└── unit/
    ├── test_security_decision_engine.py
    └── test_commit_risk_predictor.py
```

- **conftest.py**: Shared pytest fixtures for clean ML1, ML2, and ML3 DataFrames.
- **test_security_decision_engine.py**: Phase 1 Decision Engine unit tests (70 tests).
- **test_commit_risk_predictor.py**: Phase 2 ML1 Commit Risk Predictor unit tests (94 tests).

## Phase 1 — Decision Engine

**Scope**: Security Decision Engine runtime component (`ml/decision_engine/security_decision_engine.py`).

### Functions Tested

- `load_report`: File existence, malformed CSV, header-only, empty reports, missing files.
- `build_alert_summary`: Empty DataFrames, priority filtering, bounded output, summary format.
- `build_commit_risk_summary`: Empty DataFrames, risk-level filtering, bounded output, summary format.
- `get_anomaly_summary`: Empty DataFrames, normal/anomalous status, score preservation, reason fallback, missing columns with default handling.
- `calculate_decision`: Decision hierarchy, counts, reason messages, component integration, empty reports, missing columns.
- `write_decision`: CSV creation, column preservation, decision value persistence, conditional console output branches.
- `main`: Report loading, decision calculation invocation, output writing, exit behaviour.

### Main Scenarios

- **PASS**: All low-risk findings, no findings, clean reports.
- **REVIEW**: ML1 MEDIUM/REVIEW_REQUIRED, ML3 ANOMALOUS/FAILED/schema-incompatible.
- **BLOCK**: ML1 HIGH, Cppcheck HIGH, Clang HIGH, multiple blocking sources.
- **Precedence**: BLOCK overrides REVIEW.
- **Error handling**: Missing files, malformed CSV, empty reports, missing columns.

### Results

- **Tests collected**: 70
- **Tests passed**: 70
- **Tests failed**: 0
- **Coverage**: 99% (155/156 statements)
- **Uncovered**: Line 299 (`if __name__ == "__main__":` guard, expected)

## Phase 2 — ML1 Commit Risk Predictor

**Scope**: ML1 runtime helper functions (`ml/commit_risk/commit_risk_predictor.py`). Tests deterministic logic without loading real trained models or modifying Git state.

### Functions Tested

- `run_git_command`: Subprocess execution wrapper, error handling, stdout capture.
- `ensure_git_working_tree`: Git repository validation.
- `is_within_scan_path`: File path filtering against scan root.
- `resolve_diff_range`: Diff range resolution from base/head refs, default fallback.
- `get_changed_cpp_files`: C/C++ file detection, extension filtering, scan-path filtering, excluded directories.
- `parse_changed_lines_from_diff`: Unified diff parsing, hunk extraction, line number sets.
- `get_changed_lines_by_file`: Multi-file changed-line retrieval.
- `extract_function_name`: C/C++ function name extraction from signatures.
- `extract_function_spans`: Function boundary detection with brace counting.
- `extract_changed_functions`: Changed function extraction with fallback behaviour.
- `model_positive_scores`: Model score extraction with predict_proba/decision_function/predict fallback.
- `get_risk_level`: Risk threshold classification (LOW/MEDIUM/HIGH).
- `calculate_confidence`: Confidence calculation from probability scores.
- `apply_review_required`: REVIEW_REQUIRED override policy for low-confidence predictions.
- `extract_top_risky_terms`: Risky term extraction from function code.
- `build_risk_reason`: Risk reason message generation.
- `aggregate_commit_risk`: Commit-level risk aggregation from function results.
- `build_commit_metadata`: Commit metadata collection from arguments/environment/Git.
- `empty_report_df`: Empty report DataFrame schema validation.

### Main Scenarios

- **Risk thresholds**: LOW/MEDIUM/HIGH boundary testing with exact current thresholds.
- **Confidence calculation**: Low/medium/high confidence from probability scores.
- **REVIEW_REQUIRED behaviour**: LOW/MEDIUM become REVIEW_REQUIRED with low confidence; HIGH remains HIGH.
- **Git command wrapper**: Successful commands, failed commands, subprocess exceptions.
- **Git working-tree validation**: Valid/invalid repository detection.
- **Scan-path filtering**: Inside/outside scan path, nested directories, similar prefixes.
- **Diff-range resolution**: Explicit base/head, default fallback, insufficient history.
- **Changed C/C++ file detection**: Extension filtering (.c, .cpp, .h, etc.), scan-path filtering, excluded directories.
- **Diff-line parsing**: Single/multiple hunks, multiline changes, empty diff, malformed hunks.
- **Changed lines by file**: Single/multiple files, empty changes.
- **Function-name extraction**: Normal functions, namespaced functions, class methods, malformed input.
- **Function-span extraction**: Single/multiple functions, nested braces, incomplete functions, control statements.
- **Changed-function extraction**: Changes inside functions, across functions, outside functions (fallback), empty changes.
- **Model-score handling**: predict_proba, decision_function, predict-only models.
- **Risk-reason generation**: Risky terms found/not found, HIGH/MEDIUM/LOW reasons, fallback note.
- **Commit-level aggregation**: Empty results, all LOW, LOW+MEDIUM, HIGH precedence, REVIEW_REQUIRED precedence.
- **Commit metadata**: Explicit arguments, environment variables, Git command fallback.
- **Empty report schema**: DataFrame structure, column presence, zero rows, deterministic order.

### Results

- **Tests collected**: 94
- **Tests passed**: 94
- **Tests failed**: 0
- **Coverage**: 66% (233/351 statements)

### Uncovered Lines with Categorization

- **Line 59**: Error-handling path — exception handling in `run_git_command` when subprocess raises an exception.
- **Lines 119, 129**: Excluded-directory filtering — continue statements in `get_changed_cpp_files` for skipping files in `.git`, `reports`, and `.devsecops` directories.
- **Line 155**: Malformed-hunk handling — regex mismatch branch in `parse_changed_lines_from_diff` for invalid unified diff hunks.
- **Lines 220, 228-229, 232-233, 238-239, 242-243, 246-247, 253-254**: Function-signature validation — error-path branches in `extract_function_spans` for validating function signatures, detecting control statements (if/for/while/switch), handling forward declarations, and rejecting incomplete or malformed signatures.
- **Lines 295-297**: File-read error path — exception handler in `extract_changed_functions` when source file cannot be read.
- **Lines 459-675**: Main orchestration — `main()` function orchestrating argument parsing, model loading (joblib.load), TF-IDF vectorization, Git operations, function extraction, model inference, report generation, and CSV writing.
- **Line 679**: Module guard — `if __name__ == "__main__":` guard statement.

**Justification for 66% coverage**: The `main()` function (lines 459-675, 217 statements) requires real trained model files (`.pkl`), real TF-IDF vectorizers, actual Git history, and filesystem writes to `reports/`. Testing this function requires integration-test infrastructure with model artifacts and Git repositories. The remaining uncovered lines are either low-probability error paths (exception handlers, malformed input branches) or infrastructure guards (module-level guard). All deterministic helper logic and data transformations are fully tested.

## Combined Testing Results

Running the complete Phase 1 + Phase 2 test suite:

- **Total tests collected**: 164
- **Total tests passed**: 164
- **Total tests failed**: 0
- **Combined pass rate**: 100%

### Component Coverage

- **Decision Engine**: 99% coverage (155/156 statements)
- **ML1 Commit Risk Predictor**: 66% coverage (233/351 statements)
- **Combined Phase 1 and Phase 2 coverage**: 77% (388/507 statements)

