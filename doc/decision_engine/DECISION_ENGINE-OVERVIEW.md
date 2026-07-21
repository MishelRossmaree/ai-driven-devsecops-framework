# Decision Engine

## Purpose

The Security Decision Engine is the final policy layer of the framework. It consolidates outputs from ML1 commit-risk assessment, ML2 alert prioritisation (Cppcheck and Clang), and ML3 pipeline anomaly detection into a single CI/CD security outcome.

A centralized decision engine is required so that heterogeneous ML signals are resolved through one deterministic hierarchy, producing one auditable gate decision for workflow control.

## Position inside the Framework

ML1

↓

ML2

↓

ML3

↓

Security Decision Engine

↓

GitHub Action Decision

The engine receives:

- ML1 commit-risk report from reports/commit_risk/commit_risk_report.csv.
- ML2 prioritised alert reports from reports/alert_prioritizer/cppcheck/prioritised-alerts.csv and reports/alert_prioritizer/clang/prioritised-alerts.csv.
- ML3 anomaly report from reports/anomaly_detection/anomaly_report.csv.

It then emits the consolidated decision report consumed by the workflow gate.

## Runtime Workflow

Exact runtime sequence implemented in security_decision_engine.py:

Loading reports

↓

Validating reports

↓

Summarizing ML outputs

↓

Applying decision hierarchy

↓

Generating decision report

↓

Returning workflow exit code

Operational details:

1. Load each upstream report with load_report.
2. Treat missing, malformed, or empty files as empty DataFrame for that source.
3. Aggregate ML1 risk counts, ML2 priority counts, and ML3 anomaly summary fields.
4. Apply deterministic ordered decision rules.
5. Write reports/final_decision/security_decision.csv.
6. Return exit code behavior based on decision (BLOCK exits non-zero; REVIEW and PASS exit zero).

## Inputs

The Decision Engine consumes the following runtime inputs.

### ML1 reports

- reports/commit_risk/commit_risk_report.csv

Used fields:

- risk_level
- file_path
- risk_score

### ML2 reports

- reports/alert_prioritizer/cppcheck/prioritised-alerts.csv
- reports/alert_prioritizer/clang/prioritised-alerts.csv

Used fields:

- priority
- tool
- file
- line
- alert_id
- message

### ML3 report

- reports/anomaly_detection/anomaly_report.csv

Used fields:

- anomaly_status
- anomaly_score
- reason (ingested as anomaly_reason)

If ML3 report is unavailable, the engine assigns:

- anomaly_status = NOT_AVAILABLE
- anomaly_score = empty
- anomaly_reason = ML3 anomaly report not available

### GitHub Action inputs

The engine has no direct CLI arguments or action input parameters. It is executed as a fixed step in action.yml and depends on upstream component outputs that are influenced by action inputs (for example ML1 thresholds and ML3 minimum rows).

## Decision Hierarchy

The final hierarchy is deterministic and ordered exactly as implemented.

### BLOCK

Condition:

- commit_high_count > 0 OR alert_high_count > 0

Reason emitted:

- High commit risk or high severity security alerts detected

### REVIEW

Conditions evaluated in this order after BLOCK:

1. commit_review_required_count > 0
2. anomaly_status == ANOMALOUS
3. anomaly_status == NOT_AVAILABLE AND anomaly_reason contains one of:
- MISSING
- MALFORMED
- SCHEMA_MISMATCH
- schema-incompatible
- CURRENT_METRICS_SCHEMA_INCOMPATIBLE
4. anomaly_status == FAILED
5. commit_medium_count > 0 OR alert_medium_count > 0

Reason emitted is specific to the triggering rule.

### PASS

Assigned only if no BLOCK or REVIEW condition is met.

Reason emitted:

- Only low risk findings detected, if any low findings exist.
- No commit risk, security alerts, or anomaly detected, otherwise.

## Runtime Behaviour

### PASS

- Decision report is written.
- Script exits successfully.
- Workflow continues as pass.

### REVIEW

- Decision report is written.
- Script exits successfully.
- Workflow does not fail by exit code, but the output states manual security review is required.

### BLOCK

- Decision report is written.
- Script prints gate-block messaging.
- Script raises SystemExit(1), producing a non-zero workflow step outcome.

### Cold start behaviour

When ML3 is in cold-start states (for example NOT_AVAILABLE with INSUFFICIENT_HISTORY or MODEL_NOT_TRAINED), this does not trigger automatic REVIEW in the Decision Engine. The malformed/schema-not-available rule is string-matched and only applies to schema or malformed upstream-unavailability indicators.

### ML3 anomaly behaviour

- ANOMALOUS always escalates to REVIEW (unless a prior BLOCK rule already applies).
- FAILED always escalates to REVIEW (unless a prior BLOCK rule already applies).
- NOT_AVAILABLE escalates to REVIEW only when anomaly_reason matches the malformed/schema pattern set above.

### Runtime failure handling

- Missing, malformed, or empty report files are handled as empty inputs through load_report.
- The engine still attempts to compute a decision and write output under those conditions.
- Only BLOCK triggers explicit non-zero exit by design.

## Output

Generated report:

- reports/final_decision/security_decision.csv

The report contains one row with consolidated fields:

- decision
- reason
- commit_high_count
- commit_review_required_count
- commit_medium_count
- commit_low_count
- alert_high_count
- alert_medium_count
- alert_low_count
- anomaly_status
- anomaly_score
- anomaly_reason
- commit_high_issues
- commit_review_required_issues
- commit_medium_issues
- commit_low_issues
- alert_high_issues
- alert_medium_issues
- alert_low_issues

Issue summary fields include up to five examples per category, serialized as semicolon-separated text.

## GitHub Actions Integration

The action invokes the engine in the step Run final security decision engine and uploads reports/final_decision/security_decision.csv as artifact final-security-decision.

Workflow exit behavior:

- PASS: step exits 0.
- REVIEW: step exits 0.
- BLOCK: step exits 1.

This means BLOCK is the only condition that fails the gate by process exit code in the current implementation.

## Key Design Decisions

- Single centralized decision: all ML outputs are resolved in one gate component.
- Priority ordering: explicit ordered if/elif hierarchy guarantees deterministic precedence.
- ML independence: each ML signal is consumed as report data without cross-model recomputation.
- Deterministic behaviour: identical inputs produce identical decisions and reasons.
- Clear audit trail: CSV output captures counts, anomaly context, and concise issue summaries.

## Current Limitations

Only implementation-real limitations are listed.

- No strict schema validation is performed for non-empty reports before column access; malformed column structures can raise runtime exceptions.
- ML3 NOT_AVAILABLE escalation depends on substring matching inside anomaly_reason, so behaviour relies on upstream reason text conventions.
- REVIEW does not fail the workflow by exit code; enforcement is informational unless external policy treats REVIEW as blocking.
- Commit and alert issue summaries are truncated to five items per severity/risk group.
- The engine consumes only report artifacts; it does not verify whether upstream models executed with expected versions or metadata.

## Summary

The Security Decision Engine is the framework’s final deterministic gate. It merges ML1, ML2, and ML3 runtime outputs through a fixed precedence policy, writes a single auditable decision record, and enforces hard CI/CD blocking only for BLOCK outcomes via non-zero exit code.