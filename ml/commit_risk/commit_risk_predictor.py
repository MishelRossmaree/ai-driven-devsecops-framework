import argparse
import os
import re
import subprocess
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd


SUPPORTED_EXTENSIONS = [".c", ".cpp", ".cc", ".cxx", ".h", ".hpp"]

EXCLUDED_DIRS = {
    ".git",
    "reports",
    ".devsecops"
}

RISKY_TERMS = [
    "strcpy",
    "strcat",
    "sprintf",
    "vsprintf",
    "gets",
    "memcpy",
    "memmove",
    "malloc",
    "calloc",
    "realloc",
    "free",
    "buffer",
    "overflow",
    "pointer",
    "null",
    "race",
    "system",
    "exec"
]


def run_git_command(args):
    try:
        result = subprocess.run(
            ["git", *args],
            check=False,
            capture_output=True,
            text=True
        )
    except Exception:
        return ""

    if result.returncode != 0:
        return ""

    return result.stdout.strip()


def is_within_scan_path(repo_root, scan_root, relative_path):
    candidate = (repo_root / relative_path).resolve()

    try:
        candidate.relative_to(scan_root)
        return True
    except ValueError:
        return False


def resolve_diff_range(base_ref, head_ref):
    base_ref = (base_ref or "").strip()
    head_ref = (head_ref or "").strip()

    if base_ref and head_ref:
        base_ok = run_git_command(["rev-parse", "--verify", base_ref])
        head_ok = run_git_command(["rev-parse", "--verify", head_ref])

        if base_ok and head_ok:
            return f"{base_ref}...{head_ref}"

    if run_git_command(["rev-parse", "--verify", "HEAD~1"]):
        return "HEAD~1...HEAD"

    return ""


def get_changed_cpp_files(diff_range, scan_path):
    if not diff_range:
        return []

    output = run_git_command(["diff", "--name-only", diff_range])

    if not output:
        return []

    repo_root = Path.cwd().resolve()

    if Path(scan_path).is_absolute():
        scan_root = Path(scan_path).resolve()
    else:
        scan_root = (repo_root / scan_path).resolve()

    changed_files = []

    for relative in output.splitlines():
        relative = relative.strip()

        if not relative:
            continue

        relative_path = Path(relative)

        if any(part in EXCLUDED_DIRS for part in relative_path.parts):
            continue

        if relative_path.suffix.lower() not in SUPPORTED_EXTENSIONS:
            continue

        if not is_within_scan_path(repo_root, scan_root, relative_path):
            continue

        absolute_path = (repo_root / relative_path).resolve()

        if absolute_path.exists() and absolute_path.is_file():
            changed_files.append(relative_path.as_posix())

    return sorted(set(changed_files))


def parse_changed_lines_from_diff(diff_text):
    changed = set()

    for line in diff_text.splitlines():
        if not line.startswith("@@"):
            continue

        match = re.search(r"@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@", line)

        if not match:
            continue

        start = int(match.group(1))
        count = int(match.group(2) or "1")

        if count == 0:
            continue

        for line_no in range(start, start + count):
            changed.add(line_no)

    return changed


def get_changed_lines_by_file(diff_range, changed_files):
    changed_lines = {}

    for relative_path in changed_files:
        diff_text = run_git_command(["diff", "-U0", diff_range, "--", relative_path])
        changed_lines[relative_path] = parse_changed_lines_from_diff(diff_text)

    return changed_lines


def extract_function_name(signature_prefix):
    match = re.search(r"([A-Za-z_~]\w*(?:::[A-Za-z_~]\w*)*)\s*$", signature_prefix.strip())

    if match:
        return match.group(1)

    return "anonymous_function"


def extract_function_spans(source_code):
    lines = source_code.splitlines()
    functions = []
    i = 0

    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        if not stripped or stripped.startswith("#"):
            i += 1
            continue

        if "(" not in stripped and "{" not in stripped:
            i += 1
            continue

        signature_parts = []
        open_line_idx = None

        for j in range(i, min(i + 8, len(lines))):
            part = lines[j].strip()

            if not part:
                continue

            signature_parts.append(part)

            if "{" in part:
                open_line_idx = j
                break

            if ";" in part and "(" in " ".join(signature_parts):
                break

        if open_line_idx is None:
            i += 1
            continue

        signature = " ".join(signature_parts)

        if "(" not in signature or ")" not in signature:
            i += 1
            continue

        if re.search(r"\b(if|for|while|switch|catch)\s*\(", signature):
            i += 1
            continue

        if signature.lstrip().startswith(("typedef", "struct", "enum", "class", "namespace")):
            i += 1
            continue

        signature_prefix = signature.split("{", 1)[0]
        after_paren = signature_prefix.split(")", 1)[-1]

        if ";" in after_paren:
            i += 1
            continue

        function_name = extract_function_name(signature_prefix.split("(", 1)[0])

        depth = 0
        end_line_idx = None

        for k in range(open_line_idx, len(lines)):
            for char in lines[k]:
                if char == "{":
                    depth += 1
                elif char == "}":
                    depth -= 1
                    if depth == 0:
                        end_line_idx = k
                        break

            if end_line_idx is not None:
                break

        if end_line_idx is None:
            i += 1
            continue

        functions.append({
            "function_name": function_name,
            "start_line": i + 1,
            "end_line": end_line_idx + 1,
            "function_code": "\n".join(lines[i:end_line_idx + 1])
        })

        i = end_line_idx + 1

    return functions


def extract_changed_functions(repo_root, relative_path, changed_lines):
    absolute_path = (repo_root / relative_path).resolve()

    try:
        source_code = absolute_path.read_text(encoding="utf-8", errors="ignore")
    except Exception as exc:
        print(f"Could not read {relative_path}: {exc}")
        return []

    all_functions = extract_function_spans(source_code)
    selected = []

    if changed_lines:
        for item in all_functions:
            overlaps = any(item["start_line"] <= line_no <= item["end_line"] for line_no in changed_lines)

            if overlaps:
                selected.append(item)

    unique = {}

    for item in selected:
        key = (item["function_name"], item["start_line"], item["end_line"])
        unique[key] = item

    selected = list(unique.values())

    if selected:
        return [
            {
                "file_path": relative_path,
                "function_name": item["function_name"],
                "start_line": item["start_line"],
                "end_line": item["end_line"],
                "function_code": item["function_code"],
                "fallback_used": False
            }
            for item in selected
        ]

    # Fallback to full file context when function extraction fails.
    return [{
        "file_path": relative_path,
        "function_name": "__FILE_FALLBACK__",
        "start_line": 1,
        "end_line": len(source_code.splitlines()),
        "function_code": source_code,
        "fallback_used": True
    }]


def model_positive_scores(model, features):
    if hasattr(model, "predict_proba"):
        probabilities = model.predict_proba(features)
        return probabilities[:, 1]

    if hasattr(model, "decision_function"):
        raw_scores = model.decision_function(features)
        return 1 / (1 + np.exp(-raw_scores))

    predictions = model.predict(features)
    return predictions.astype(float)


def get_risk_level(probability, medium_threshold, high_threshold):
    risk_score = round(float(probability) * 100, 2)

    if risk_score >= high_threshold:
        return risk_score, "HIGH"
    if risk_score >= medium_threshold:
        return risk_score, "MEDIUM"
    return risk_score, "LOW"


def calculate_confidence(probability):
    return round(abs(float(probability) - 0.5) * 2, 4)


def apply_review_required(risk_level, confidence, confidence_threshold):
    if confidence < confidence_threshold and risk_level != "HIGH":
        return "REVIEW_REQUIRED"
    return risk_level


def extract_top_risky_terms(function_code):
    lowered = function_code.lower()
    terms = [term for term in RISKY_TERMS if term in lowered]
    return terms[:5]


def build_risk_reason(risk_level, terms, fallback_used, confidence, confidence_threshold):
    if risk_level == "REVIEW_REQUIRED":
        reason = (
            f"REVIEW_REQUIRED because model confidence ({confidence}) is below "
            f"threshold ({confidence_threshold})."
        )
        if terms:
            reason += f" Potential risky terms include {', '.join(terms[:3])}."
    elif terms:
        reason = f"{risk_level} because modified function contains {', '.join(terms[:3])} patterns."
    elif risk_level == "HIGH":
        reason = "HIGH based on model confidence for vulnerable code patterns."
    elif risk_level == "MEDIUM":
        reason = "MEDIUM based on model confidence for potentially risky code patterns."
    else:
        reason = "LOW because no strong vulnerable pattern signals were detected."

    if fallback_used:
        reason += " Function extraction failed, so full-file fallback analysis was used."

    return reason


def aggregate_commit_risk(function_levels):
    if "HIGH" in function_levels:
        return "HIGH"
    if "REVIEW_REQUIRED" in function_levels:
        return "REVIEW_REQUIRED"
    if "MEDIUM" in function_levels:
        return "MEDIUM"
    if "LOW" in function_levels:
        return "LOW"
    return "SKIPPED"


def build_commit_metadata(args):
    commit_sha = args.commit_sha or os.getenv("GITHUB_SHA", "") or run_git_command(["rev-parse", "HEAD"])
    branch = args.branch or os.getenv("GITHUB_REF_NAME", "")
    event_type = args.event_type or os.getenv("GITHUB_EVENT_NAME", "")
    author = args.author or os.getenv("GITHUB_ACTOR", "") or run_git_command(["show", "-s", "--format=%an", "HEAD"])

    base_ref = args.base_ref or os.getenv("GITHUB_BASE_REF", "")
    head_ref = args.head_ref or os.getenv("GITHUB_HEAD_REF", "")

    return {
        "commit_sha": commit_sha,
        "branch": branch,
        "event_type": event_type,
        "author": author,
        "base_ref": base_ref,
        "head_ref": head_ref
    }


def empty_report_df():
    return pd.DataFrame(columns=[
        "commit_sha",
        "branch",
        "event_type",
        "author",
        "base_ref",
        "head_ref",
        "file_path",
        "function_name",
        "start_line",
        "end_line",
        "risk_score",
        "risk_level",
        "confidence",
        "review_confidence_threshold",
        "top_risky_terms",
        "risk_reason",
        "vectorization_time_ms",
        "model_inference_time_ms",
        "total_prediction_runtime_ms"
    ])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--scan-path", required=True)
    parser.add_argument("--model-path", required=True)
    parser.add_argument("--vectorizer-path", required=True)
    parser.add_argument("--high-threshold", type=float, default=70.0)
    parser.add_argument("--medium-threshold", type=float, default=40.0)
    parser.add_argument("--review-confidence-threshold", type=float, default=0.2)
    parser.add_argument("--commit-sha", default="")
    parser.add_argument("--branch", default="")
    parser.add_argument("--event-type", default="")
    parser.add_argument("--author", default="")
    parser.add_argument("--base-ref", default="")
    parser.add_argument("--head-ref", default="")
    parser.add_argument(
        "--output",
        default="reports/commit_risk/commit_risk_report.csv"
    )
    parser.add_argument(
        "--summary-output",
        default="reports/commit_risk/commit_risk_summary.csv"
    )

    args = parser.parse_args()

    prediction_start = time.perf_counter()

    if args.medium_threshold >= args.high_threshold:
        raise ValueError("medium-threshold must be lower than high-threshold")

    if args.review_confidence_threshold < 0 or args.review_confidence_threshold > 1:
        raise ValueError("review-confidence-threshold must be between 0 and 1")

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    summary_output_path = Path(args.summary_output)
    summary_output_path.parent.mkdir(parents=True, exist_ok=True)

    metadata = build_commit_metadata(args)

    diff_range = resolve_diff_range(metadata["base_ref"], metadata["head_ref"])
    changed_files = get_changed_cpp_files(diff_range, args.scan_path)

    if not changed_files:
        print("No C/C++ changes detected. ML1 skipped.")
        empty_report_df().to_csv(output_path, index=False)

        summary_row = {
            **metadata,
            "total_changed_files": 0,
            "total_changed_functions": 0,
            "high_risk_functions": 0,
            "review_required_functions": 0,
            "medium_risk_functions": 0,
            "low_risk_functions": 0,
            "max_risk_score": 0.0,
            "commit_risk_level": "SKIPPED",
            "vectorization_time_ms": 0.0,
            "model_inference_time_ms": 0.0,
            "total_prediction_runtime_ms": round((time.perf_counter() - prediction_start) * 1000, 2)
        }

        pd.DataFrame([summary_row]).to_csv(summary_output_path, index=False)
        return

    changed_lines_by_file = get_changed_lines_by_file(diff_range, changed_files)

    repo_root = Path.cwd().resolve()
    function_items = []

    for relative_path in changed_files:
        file_items = extract_changed_functions(
            repo_root,
            relative_path,
            changed_lines_by_file.get(relative_path, set())
        )
        function_items.extend(file_items)

    if not function_items:
        print("No analyzable changed functions found. ML1 skipped.")
        empty_report_df().to_csv(output_path, index=False)
        return

    model = joblib.load(args.model_path)
    vectorizer = joblib.load(args.vectorizer_path)

    functions_df = pd.DataFrame(function_items)

    vectorization_start = time.perf_counter()
    features = vectorizer.transform(functions_df["function_code"])
    vectorization_time_ms = round((time.perf_counter() - vectorization_start) * 1000, 2)

    inference_start = time.perf_counter()
    probabilities = model_positive_scores(model, features)
    model_inference_time_ms = round((time.perf_counter() - inference_start) * 1000, 2)

    rows = []
    levels = []

    for index, row in functions_df.iterrows():
        risk_score, risk_level = get_risk_level(
            probabilities[index],
            args.medium_threshold,
            args.high_threshold
        )

        confidence = calculate_confidence(probabilities[index])
        risk_level = apply_review_required(
            risk_level,
            confidence,
            args.review_confidence_threshold
        )

        terms = extract_top_risky_terms(row["function_code"])
        risk_reason = build_risk_reason(
            risk_level,
            terms,
            row["fallback_used"],
            confidence,
            args.review_confidence_threshold
        )

        levels.append(risk_level)

        rows.append({
            **metadata,
            "file_path": row["file_path"],
            "function_name": row["function_name"],
            "start_line": row["start_line"],
            "end_line": row["end_line"],
            "risk_score": risk_score,
            "risk_level": risk_level,
            "confidence": confidence,
            "review_confidence_threshold": args.review_confidence_threshold,
            "top_risky_terms": "|".join(terms),
            "risk_reason": risk_reason,
            "vectorization_time_ms": vectorization_time_ms,
            "model_inference_time_ms": model_inference_time_ms,
            "total_prediction_runtime_ms": 0.0
        })

    report_df = pd.DataFrame(rows)
    total_runtime_ms = round((time.perf_counter() - prediction_start) * 1000, 2)
    report_df["total_prediction_runtime_ms"] = total_runtime_ms
    report_df.to_csv(output_path, index=False)

    summary_row = {
        **metadata,
        "total_changed_files": len(changed_files),
        "total_changed_functions": len(report_df),
        "high_risk_functions": int(report_df["risk_level"].eq("HIGH").sum()),
        "review_required_functions": int(report_df["risk_level"].eq("REVIEW_REQUIRED").sum()),
        "medium_risk_functions": int(report_df["risk_level"].eq("MEDIUM").sum()),
        "low_risk_functions": int(report_df["risk_level"].eq("LOW").sum()),
        "max_risk_score": float(report_df["risk_score"].max()) if not report_df.empty else 0.0,
        "commit_risk_level": aggregate_commit_risk(levels),
        "vectorization_time_ms": vectorization_time_ms,
        "model_inference_time_ms": model_inference_time_ms,
        "total_prediction_runtime_ms": total_runtime_ms
    }

    pd.DataFrame([summary_row]).to_csv(summary_output_path, index=False)

    print("\nCommit Risk Prediction Completed")
    print(report_df)
    print(f"\nDetailed report saved to: {output_path}")
    print(f"Summary report saved to: {summary_output_path}")


if __name__ == "__main__":
    main()
