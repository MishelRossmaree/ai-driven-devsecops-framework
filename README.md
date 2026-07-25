# AI-Driven DevSecOps Framework 

This repository contains an MSc dissertation framework implementing an
AI-driven DevSecOps pipeline with GitHub Actions for C/C++ security
analysis. It combines ML1 Commit Risk Prediction, ML2 Static Analysis
Alert Prioritization, ML3 Pipeline Anomaly Detection, and a Security
Decision Engine into one integrated workflow. The frozen implementation
produces deterministic, explainable CI/CD security decisions from
component reports.

## Overview

This framework operationalizes AI-assisted DevSecOps by integrating four
runtime components in a single CI/CD workflow:

-   ML1 commit risk prediction
-   ML2 static-analysis alert prioritization
-   ML3 pipeline anomaly detection
-   Security Decision Engine

The implementation is frozen and designed around generated reports as
the contract between components, allowing deterministic, auditable
security decisions during pull request and push workflows.

## Framework Architecture

``` mermaid
flowchart TD
    A[GitHub Workflow Trigger] --> B[ML1 Commit Risk Prediction]
    B --> C[ML2 Static Analysis Alert Prioritization]
    C --> D[ML3 Pipeline Anomaly Detection]
    D --> E[Security Decision Engine]
    E --> F[PASS / REVIEW / BLOCK]
```

## Key Features

-   Commit-level risk prediction from changed C/C++ functions (ML1).
-   Static-analysis alert prioritization for Cppcheck and Clang outputs
    (ML2).
-   Repository-specific behavioural anomaly detection using historical
    pipeline metrics (ML3).
-   Centralized deterministic decision hierarchy that outputs PASS,
    REVIEW, or BLOCK.
-   Composite GitHub Action integration for end-to-end CI/CD execution.
-   Explainable report artifacts with counts, reasons, and concise issue
    summaries.
-   Optional persistence of ML3 historical state to the consuming
    repository.

## Repository Structure

``` text
.
|-- action.yml
|-- README.md
|-- requirements.txt
|-- doc/
|-- ml/
|-- models/
|-- data/                  # Generated locally during preprocessing (not included)
|-- reports/
`-- logs/
```

## Framework Workflow

The composite action in `action.yml` executes the runtime sequence
below.

1.  Install SAST tooling and Python dependencies.
2.  Run Cppcheck and Clang Static Analyzer scans.
3.  Run ML1 commit risk prediction.
4.  Run ML2 Cppcheck alert prioritization.
5.  Run ML2 Clang alert prioritization.
6.  Run ML3 metrics collection, model training/update, and anomaly
    detection.
7.  Optionally persist ML3 state under `.devsecops/anomaly_detection`.
8.  Run the Security Decision Engine and emit the final decision report.
9.  Upload generated artifacts.

## Components

### ML1

Produces commit risk reports consumed by downstream components.

### ML2

Prioritises Cppcheck and Clang static-analysis alerts.

### ML3

Performs repository-specific anomaly detection using historical pipeline
metrics.

### Security Decision Engine

Combines ML1, ML2 and ML3 outputs into a final PASS, REVIEW or BLOCK
decision.

## Installation

### Prerequisites

* Python 3.13
* Git and Git LFS
* GitHub Actions Ubuntu runner (`ubuntu-latest`)
* Cppcheck
* Clang
* Clang Tools

### Technology Stack

The framework uses the following languages, libraries, tools, and platforms:

* Python 3.13 for machine learning, data processing, report generation, and decision logic.
* C and C++ as the target source-code languages analysed by the framework.
* YAML for GitHub Actions workflow and composite action configuration.
* Bash for command execution and orchestration within the GitHub Actions environment.
* GitHub Actions for CI/CD integration and automated framework execution.
* scikit-learn for machine learning model training, evaluation, and inference.
* pandas for dataset processing, report handling, and pipeline metrics management.
* NumPy and SciPy for numerical and scientific computing.
* joblib for serialising and loading trained machine learning models.
* Cppcheck for static analysis of C/C++ source code.
* Clang Static Analyzer and Clang Tools for C/C++ static analysis.
* Git for source-code version control and change-based analysis.
* Git LFS for storing and distributing trained machine learning model artefacts.

### Software Requirements

The framework was tested with the following software environment:

* Python 3.13
* Git
* Git LFS
* GitHub Actions Ubuntu runner (`ubuntu-latest`)
* Cppcheck
* Clang
* Clang Tools
* Python dependencies listed in `requirements.txt`

The composite GitHub Action installs Cppcheck, Clang, and Clang Tools from the package versions available on the `ubuntu-latest` GitHub Actions runner at execution time. Exact scanner versions may therefore depend on the Ubuntu runner image used for a particular workflow run.

### Hardware Requirements

The framework does not require GPU acceleration.

Recommended minimum environment:

* Standard 64-bit CPU
* 8 GB RAM
* Sufficient storage for the repository, trained model artefacts, generated reports, and Git LFS files
* Internet access during initial setup to install dependencies, retrieve Git LFS model files, and install static-analysis tools

Model inference and normal GitHub Action execution can run on a standard GitHub-hosted Ubuntu runner.


### Python dependencies

The framework uses the pinned Python dependencies specified in
`requirements.txt`.

``` bash
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt
```

The composite GitHub Action installs the same dependencies
automatically.

### Repository checkout

``` yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0
```

### Git LFS

The trained machine learning models are stored using Git Large File
Storage (Git LFS).

``` bash
git lfs install
git clone <repository-url>
cd ai-driven-devsecops-framework
git lfs pull
```

All trained `.pkl` model files under `models/` are managed through Git
LFS.

### Local Installation

``` bash
git clone <repository-url>
cd ai-driven-devsecops-framework
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt
```

## Dataset Preparation

The framework was developed using publicly available datasets for model
training and evaluation.

The original datasets are not included in this repository because of
their size and licensing restrictions.

Dataset preparation and preprocessing instructions are provided in the
component guides under `doc/`.

The repository includes the final trained models required for framework
execution. Retraining is only necessary to reproduce the experiments
described in the dissertation.

## Dataset Preparation

The original training datasets are not included in this repository because of their size and, where applicable, dataset licensing and redistribution restrictions.

The repository contains the preprocessing, conversion, feature-engineering, training, and evaluation scripts required to reproduce the machine learning datasets and model artefacts used in the dissertation.

### ML1 Commit Risk Prediction

ML1 uses the PRIMEVUL dataset for vulnerable and non-vulnerable C/C++ function samples.

The dataset preparation process includes:

1. Downloading the PRIMEVUL dataset from its original source.
2. Converting the source dataset into the CSV structure required by the framework.
3. Separating the data into training, validation, and test datasets.
4. Generating TF-IDF features from C/C++ function code.
5. Training and evaluating the commit risk prediction models.

Relevant scripts and documentation:

* `ml/commit_risk/primevul_to_dataset.py`
* `ml/commit_risk/prepare_commit_features.py`
* `ml/commit_risk/train_commit_risk_model.py`
* `doc/ML1/ML1-guide.md`
* `doc/ML1/ML1-OVERVIEW.md`

### ML2 Static Analysis Alert Prioritization

ML2 uses static-analysis findings derived from C/C++ vulnerability datasets and scanner outputs.

The preparation process includes:

1. Preparing vulnerable and non-vulnerable C/C++ source samples.
2. Running Cppcheck or Clang Static Analyzer against the source files.
3. Converting the scanner outputs into structured training datasets.
4. Preparing features required by the alert prioritisation models.
5. Training and evaluating separate models for Cppcheck and Clang outputs.

Relevant scripts and documentation:

* AW4C conversion and preprocessing scripts
* Juliet dataset conversion and preprocessing scripts
* `ml/alert_prioritizer/prepare_clang_features.py`
* `ml/alert_prioritizer/train_cppcheck_model.py`
* `ml/alert_prioritizer/train_clang_model.py`
* `doc/ML2/ML2-CPPCHECK-GUIDE.md`
* `doc/ML2/ML2-CPPCHECK-OVERVIEW.md`
* `doc/ML2/ML2-CLANG-GUIDE.md`
* `doc/ML2/ML2-CLANG-OVERVIEW.md`

### ML3 Pipeline Anomaly Detection

ML3 uses repository-specific historical CI/CD pipeline metrics rather than a fixed external dataset.

The preparation process includes:

1. Collecting metrics from ML1 and ML2 runtime reports.
2. Storing valid historical pipeline records in CSV format.
3. Filtering invalid, failed, or incomplete historical records.
4. Training anomaly detection models when the minimum number of valid rows is available.
5. Evaluating the selected anomaly detection approach using generated evaluation reports.

Relevant scripts and documentation:

* `ml/anomaly_detection/pipeline_metrics_collector.py`
* `ml/anomaly_detection/train_anomaly_model.py`
* `ml/anomaly_detection/anomaly_detector.py`
* `doc/ML3/ML3-GUIDE.md`
* `doc/ML3/ML3-OVERVIEW.md`

### Generated Data Locations

Dataset files produced during preprocessing are stored locally under the `data/` directory.

Typical generated locations include:

* `data/raw/`
* `data/processed/`
* `data/intermediate/`
* `data/features/`

These generated datasets are not committed to the repository. The final trained model artefacts required for normal framework execution are included under `models/` and are managed using Git LFS.

Retraining is not required to run the framework. It is only necessary when reproducing the model-development and evaluation process described in the dissertation.


## Usage

Use the composite GitHub Action as described in the original README.

> **Note**
>
> The workflow installs all required Python dependencies automatically
> using `requirements.txt`.

## Generated Reports

-   ML1: `reports/commit_risk/`
-   ML2: `reports/alert_prioritizer/`
-   ML3: `reports/anomaly_detection/`
-   Decision Engine: `reports/final_decision/`

## Trained Models

The repository includes the final trained machine learning models used
for the dissertation evaluation.

The models are stored under the `models/` directory and are managed
using Git LFS. Retraining is not required to execute the framework.

## Decision Outcomes

-   PASS
-   REVIEW
-   BLOCK

## Documentation

Refer to the documentation under the `doc/` directory for ML1, ML2, ML3
and the Decision Engine.

## Automated Testing

The framework includes an automated test suite for the Security Decision Engine. Phase 1 testing validates deterministic decision logic, report processing, error handling, and integration behaviour.

### Running tests

```bash
python3 -m pytest tests/unit/test_security_decision_engine.py -v
```

### Coverage reports

Terminal coverage with missing lines:

```bash
python3 -m pytest tests/unit/test_security_decision_engine.py \
  --cov=ml.decision_engine \
  --cov-report=term-missing
```

**Phase 1 results**: 70 tests, 99% Decision Engine coverage.

For detailed test design, scenarios, known limitations, and coverage interpretation, see [doc/TESTING.md](doc/TESTING.md).

## Limitations

Only implementation-real limitations are listed.

## Future Enhancements

The following are prospective improvements and are not part of the
frozen implementation.

## License

This repository was developed as part of an MSc dissertation submitted
to the University of Westminster.

The source code is provided for academic evaluation and research
purposes. Redistribution or commercial use of this work requires the
permission of the author.
