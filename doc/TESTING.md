# Automated Testing

## 1. Purpose

The automated test suite verifies the framework's deterministic application logic, report processing, decision rules, error behaviour, and component integration. Tests ensure that the Security Decision Engine correctly loads, parses, and combines component reports to produce consistent, auditable PASS, REVIEW, or BLOCK decisions.

Model evaluation metrics (precision, recall, F1-score, confusion matrices) are separate from software test coverage. Test coverage demonstrates that decision logic branches, error-handling paths, and integration scenarios have been exercised, while model quality evidence comes from validation and test evaluation artefacts stored in `reports/`.

## 2. Testing tools

The Phase 1 test suite uses:

- **pytest**: Test execution and collection framework.
- **pytest-cov**: Code coverage measurement and reporting.
- **pandas**: Test fixtures and DataFrame assertions.
- **monkeypatch** (pytest fixture): Isolates tests by replacing module constants, functions, and current working directory.
- **tmp_path** (pytest fixture): Provides temporary directories for file I/O without modifying the real repository reports structure.
- **capsys** (pytest fixture): Captures and verifies console output from the Decision Engine.

## 3. Test structure

The current Phase 1 test structure is:

```
tests/
├── conftest.py
└── unit/
    └── test_security_decision_engine.py
```

- **conftest.py**: Contains shared pytest fixtures for clean ML1, ML2, and ML3 DataFrames.
- **test_security_decision_engine.py**: Contains all Decision Engine unit tests.

### Planned later phases

The following test modules are planned for future phases but are **not yet implemented**:

- ML1 Commit Risk Predictor tests
- ML2 Cppcheck alert prioritizer tests
- ML2 Clang alert prioritizer tests
- ML3 anomaly detection tests
- Integration and model-loading smoke tests

## 4. Phase 1 coverage

The Phase 1 test suite validates all Security Decision Engine functionality:

### Functions tested

- `load_report`: File existence, malformed CSV, header-only, empty reports, missing files.
- `build_alert_summary`: Empty DataFrames, priority filtering, bounded output (max_items), summary format.
- `build_commit_risk_summary`: Empty DataFrames, risk-level filtering, bounded output, summary format.
- `get_anomaly_summary`: Empty DataFrames, normal/anomalous status, score preservation, reason fallback, missing columns with default handling.
- `calculate_decision`: Decision hierarchy, counts, reason messages, component integration, empty reports, missing columns (KeyError behaviour).
- `write_decision`: CSV creation, column preservation, decision value persistence, conditional console output branches.
- `main`: Report loading, decision calculation, output writing, exit behaviour for PASS/REVIEW/BLOCK.

### Decision scenarios tested

- **PASS**: All low-risk findings, no findings, clean reports.
- **REVIEW**: ML1 MEDIUM risk, ML1 REVIEW_REQUIRED, ML3 ANOMALOUS, ML3 FAILED, ML3 schema-incompatible/malformed input.
- **BLOCK**: ML1 HIGH risk, Cppcheck HIGH priority, Clang HIGH priority, multiple blocking sources.
- **Precedence**: BLOCK takes precedence over REVIEW.

### Error and edge-case scenarios tested

- **Missing report files**: `load_report` returns empty DataFrames without raising exceptions.
- **Malformed CSV files**: Unclosed quotes, parser errors result in empty DataFrames.
- **Header-only CSV files**: Treated as empty reports.
- **Wrong schema columns**: Parseable CSVs with unexpected columns are returned as-is; schema validation occurs in `calculate_decision`.
- **Missing required columns**:
  - ML1 missing `risk_level`: Raises `KeyError`.
  - Cppcheck/Clang missing `priority`: Raises `KeyError`.
  - ML3 missing `anomaly_status`: Handled gracefully with default value `"NOT_AVAILABLE"` (uses `.get()` with default).
- **Empty DataFrames**: All empty reports produce PASS under current policy.
- **Combined missing reports**: Documents current fail-open policy where all missing component reports result in PASS.

### Output and integration scenarios tested

- **write_decision conditional branches**: Verified console output for non-empty commit HIGH, REVIEW_REQUIRED, MEDIUM issues; alert HIGH, MEDIUM, LOW issues.
- **main() entry point**: Report loading, decision calculation invocation, output writing, exit codes (0 for PASS/REVIEW, 1 for BLOCK).

## 5. Running the tests

### Environment setup

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements-dev.txt
```

### Execute tests

Run all Decision Engine tests with verbose output:

```bash
python3 -m pytest tests/unit/test_security_decision_engine.py -v
```

### Generate coverage reports

**Terminal coverage with missing lines**:

```bash
python3 -m pytest tests/unit/test_security_decision_engine.py \
  --cov=ml.decision_engine \
  --cov-report=term-missing
```

**HTML coverage report**:

```bash
python3 -m pytest tests/unit/test_security_decision_engine.py \
  --cov=ml.decision_engine \
  --cov-report=html
```

The HTML report is generated in `htmlcov/index.html`. Open this file in a web browser to explore line-by-line coverage.

**XML coverage report** (for CI integration):

```bash
python3 -m pytest tests/unit/test_security_decision_engine.py \
  --cov=ml.decision_engine \
  --cov-report=xml
```

The XML report is generated as `coverage.xml`.

**Important**: `htmlcov/` and `coverage.xml` are generated locally or in CI and should not be committed. These artefacts are excluded in `.gitignore`.

Do not use `--break-system-packages` when installing dependencies; always use a virtual environment.

## 6. Test isolation

All tests use isolated temporary directories and mocked functions to ensure:

- Temporary directories (`tmp_path`) are used for file I/O; the real `reports/` directory is never modified.
- No trained model artefacts under `models/` are loaded or modified.
- Production decision rules and logic are not changed by the tests.
- No network access is used.
- Tests run independently and can execute in any order.

The `monkeypatch` fixture is used to:

- Replace `os.chdir()` to redirect relative paths to temporary directories.
- Mock `load_report`, `calculate_decision`, and `write_decision` when testing `main()`.
- Replace module constants when necessary.

## 7. Current results

**Phase 1 test execution (2026-07-26)**:

- **Tests collected**: 70
- **Tests passed**: 70
- **Tests failed**: 0
- **Decision Engine coverage**: 99% (155/156 statements covered)

**Uncovered line**:

- Line 299: `if __name__ == "__main__":` — This line is the module-level guard and is expected to remain uncovered in unit tests. It is not executed during pytest imports.

## 8. Known limitations

The Phase 1 test suite documents the following current production behaviours and limitations:

1. **Missing or unreadable report files**: `load_report` converts missing files and malformed CSV files to empty DataFrames. This may mask upstream failures.

2. **Empty report fail-open policy**: When all expected ML1, Cppcheck, and Clang component reports are empty or missing, `calculate_decision` produces a `PASS` decision under the current implementation. This fail-open policy is intentional but may not be suitable for all production environments.

3. **Missing required columns**:
   - ML1 DataFrames missing the `risk_level` column raise `KeyError` from pandas `.eq()` operations.
   - Cppcheck and Clang DataFrames missing the `priority` column raise `KeyError` during alert counting.
   - ML3 DataFrames missing the `anomaly_status` column are handled gracefully by `get_anomaly_summary`, which uses a default value of `"NOT_AVAILABLE"`.
   - Schema validation is not enforced in `load_report`; missing columns are only detected during decision calculation.

4. **Model accuracy and quality**: pytest code coverage does not measure ML model quality. Model performance evidence is found in validation and test evaluation reports under `reports/commit_risk/`, `reports/alert_prioritizer/cppcheck/`, `reports/alert_prioritizer/clang/`, and `reports/anomaly_detection/`.

5. **Scanner execution and GitHub Actions behaviour**: Static-analysis scanner execution, ML component runtime behaviour, and complete end-to-end GitHub Action workflow behaviour will be tested separately using functional and integration tests in future phases.

These behaviours were **documented, not changed**, during Phase 1 testing. They represent the current frozen production implementation.

## 9. Coverage interpretation

A high coverage percentage (99% in Phase 1) demonstrates that the automated test suite exercised nearly all decision logic branches, error-handling paths, and scenarios in the Security Decision Engine. However, high code coverage does not by itself prove:

- Complete correctness of decision logic.
- Model prediction quality.
- Absence of all possible runtime errors.
- Suitability of the fail-open policy for all environments.

**Model quality evidence** comes from separate artefacts:

- Validation results (`validation_model_comparison.csv`)
- Test evaluation results (`test_evaluation.csv`)
- Precision, recall, and F1-score metrics
- Confusion matrices
- Model metadata (`model_metadata.json`)

Code coverage ensures that deterministic application logic has been tested; model evaluation artefacts demonstrate prediction performance on held-out datasets.

## 10. Next steps

Phase 1 testing is complete. Future phases will add:

- ML1 Commit Risk Predictor runtime tests.
- ML2 Cppcheck and Clang prioritizer runtime tests.
- ML3 anomaly detection model and metrics collection tests.
- Integration tests combining all components.
- Functional tests for GitHub Actions workflow execution.
- CI/CD integration for automated test execution on pull requests.

These tests are **not yet implemented** and are outside the scope of Phase 1.
