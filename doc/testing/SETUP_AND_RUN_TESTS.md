# Test Setup and Execution Guide

This guide provides step-by-step instructions for setting up the test environment and running automated tests for the AI-Driven DevSecOps Framework.

## Prerequisites

- **Python 3.13** (the version used by this project)
- **Git** installed and available in PATH
- Repository cloned locally
- **Virtual environment recommended** (do not use `--break-system-packages`)

GPU acceleration is not required for running tests.

## 1. Create the Virtual Environment

### macOS/Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### Windows

```cmd
python -m venv .venv
.venv\Scripts\activate
```

## 2. Install Dependencies

```bash
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements-dev.txt
```

**What this installs**:

- `requirements-dev.txt` includes `requirements.txt` (runtime dependencies) plus testing dependencies:
  - `pytest==8.4.1`
  - `pytest-cov==6.2.1`

Do not use `--break-system-packages`. Always use a virtual environment.

## 3. Run Phase 1 Only (Decision Engine)

```bash
python3 -m pytest tests/unit/test_security_decision_engine.py -v
```

**Expected output**: 70 tests passed.

## 4. Run Phase 2 Only (ML1 Commit Risk Predictor)

```bash
python3 -m pytest tests/unit/test_commit_risk_predictor.py -v
```

**Expected output**: 94 tests passed.

## 5. Run Phase 1 and Phase 2 Together

```bash
python3 -m pytest tests/unit -v
```

**Expected output**: 164 tests passed.

## 6. Run Decision Engine Coverage

```bash
python3 -m pytest tests/unit/test_security_decision_engine.py \
  --cov=ml.decision_engine.security_decision_engine \
  --cov-report=term-missing
```

**Expected coverage**: 99% (155/156 statements).

## 7. Run ML1 Coverage

```bash
python3 -m pytest tests/unit/test_commit_risk_predictor.py \
  --cov=ml.commit_risk.commit_risk_predictor \
  --cov-report=term-missing
```

**Expected coverage**: 66% (233/351 statements).

**Note**: The main() function (lines 459-675, 217 statements) requires real trained models and Git operations, which are deferred to integration tests. All deterministic helper logic is fully tested.

## 8. Run Combined Phase 1 and Phase 2 Coverage

```bash
python3 -m pytest tests/unit \
  --cov=ml.decision_engine.security_decision_engine \
  --cov=ml.commit_risk.commit_risk_predictor \
  --cov-report=term-missing
```

**Expected combined coverage**: 77% (388/507 statements).

This command runs all current unit tests and reports module-specific coverage for both the Decision Engine and ML1 Commit Risk Predictor.

## 9. Generate HTML Coverage

```bash
python3 -m pytest tests/unit \
  --cov=ml.decision_engine.security_decision_engine \
  --cov=ml.commit_risk.commit_risk_predictor \
  --cov-report=html
```

**View the report**:

```bash
open htmlcov/index.html  # macOS
xdg-open htmlcov/index.html  # Linux
start htmlcov/index.html  # Windows
```

The `htmlcov/` directory is generated locally and ignored by Git.

## 10. Generate XML Coverage

```bash
python3 -m pytest tests/unit \
  --cov=ml.decision_engine \
  --cov=ml.commit_risk \
  --cov-report=xml
```

The `coverage.xml` file is generated and ignored by Git. This format is useful for CI/CD integration.

## 11. Common Issues

### Issue: `pytest: command not found`

**Solution**: Ensure the virtual environment is activated and pytest is installed.

```bash
source .venv/bin/activate  # macOS/Linux
python3 -m pip install pytest pytest-cov
```

### Issue: Virtual environment not activated

**Solution**: Activate the virtual environment before running tests.

```bash
source .venv/bin/activate  # macOS/Linux
.venv\Scripts\activate  # Windows
```

### Issue: Dependency import error

**Solution**: Install dependencies from `requirements-dev.txt`.

```bash
python3 -m pip install -r requirements-dev.txt
```

### Issue: Wrong working directory

**Solution**: Run pytest from the repository root directory.

```bash
cd /path/to/ai-driven-devsecops-framework
python3 -m pytest tests/unit -v
```

### Issue: Stale `.coverage` data

**Solution**: Remove stale coverage data files.

```bash
rm -f .coverage .coverage.*
python3 -m pytest tests/unit --cov=ml.decision_engine --cov=ml.commit_risk
```

### Issue: Tests unexpectedly touching local Git state

**Solution**: All Git operations are mocked in unit tests. If you see unexpected Git behaviour, verify that:

- Tests are running from `tests/unit/`, not an integration test directory.
- `monkeypatch` is correctly mocking `run_git_command` and subprocess calls.

## 12. Expected Current Results

### Phase 1 — Decision Engine

- **Tests collected**: 70
- **Tests passed**: 70
- **Tests failed**: 0
- **Coverage**: 99%

### Phase 2 — ML1 Commit Risk Predictor

- **Tests collected**: 92
- **Tests passed**: 92
- **Tests failed**: 0
- **Coverage**: 66%

### Combined Suite

- **Total tests collected**: 162
- **Total tests passed**: 162
- **Total tests failed**: 0
- **Combined pass rate**: 100%

**Last verified**: 2026-07-26

## Notes

- Generated coverage artifacts (`htmlcov/`, `coverage.xml`, `.coverage`) are ignored by Git.
- Tests use isolated temporary directories and mocked dependencies; they do not modify production files, reports, or models.
- Model accuracy is measured separately using validation datasets, not pytest coverage.
- Complete GitHub Action workflow behaviour is tested in a separate functional test repository.
