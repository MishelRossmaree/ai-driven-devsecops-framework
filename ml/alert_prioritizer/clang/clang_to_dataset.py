import hashlib
import os
import plistlib
import re
from pathlib import Path

import pandas as pd


RAW_OUTPUT_DIR = Path("data/intermediate/alert_prioritizer/clang/raw_outputs")
OUTPUT_FILE = Path("data/processed/alert_prioritizer/clang/clang_alert_annotation.csv")

BAD_PATTERN = re.compile(r"(?:^|[_])(bad(?:Sink|Source)?)(?:[_]|$)", re.IGNORECASE)
GOOD_PATTERN = re.compile(r"(?:^|[_])(good(?:G2B|B2G)?)(?:[_]|$)", re.IGNORECASE)
MESSAGE_NOISE_PATTERN = re.compile(r"\s*\[[^\]]+\]\s*$")
PUNCTUATION_PATTERN = re.compile(r"^[\s\W_]+|[\s\W_]+$")
FUNCTION_DEF_PATTERN = re.compile(
    r"^\s*(?:static\s+)?(?:void|int|char|short|long|float|double|bool|size_t|unsigned|signed|struct\s+[A-Za-z_][A-Za-z0-9_]*)\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(",
    re.MULTILINE,
)


def normalize_case_id(stem):
    return re.sub(r"([0-9])[a-e]$", r"\1", stem)


def normalize_path_text(path_text):
    if not path_text:
        return ""

    normalized = str(path_text).strip().replace("\\", "/")
    normalized = re.sub(r"/+", "/", normalized)
    return normalized


def path_suffixes(path_text):
    normalized = normalize_path_text(path_text)
    if not normalized:
        return []

    parts = [part for part in normalized.split("/") if part]
    return ["/".join(parts[index:]) for index in range(len(parts))]


def choose_plist_source_file(txt_source_file, plist_source_files):
    normalized_txt = normalize_path_text(txt_source_file)
    if not normalized_txt or not plist_source_files:
        return ""

    normalized_candidates = {}
    for candidate in plist_source_files:
        normalized_candidates[normalize_path_text(candidate)] = candidate

    exact = normalized_candidates.get(normalized_txt)
    if exact:
        return exact

    suffix_matches = []
    txt_suffixes = path_suffixes(normalized_txt)
    candidate_suffix_map = {}
    for candidate, original in normalized_candidates.items():
        candidate_suffix_map.setdefault(candidate, original)
        for suffix in path_suffixes(candidate):
            candidate_suffix_map.setdefault(suffix, original)

    for suffix in txt_suffixes:
        match = candidate_suffix_map.get(suffix)
        if match:
            suffix_matches.append(match)

    unique_matches = list(dict.fromkeys(suffix_matches))
    if len(unique_matches) == 1:
        return unique_matches[0]

    return ""


def normalize_message_text(message):
    text = str(message or "").strip()
    text = MESSAGE_NOISE_PATTERN.sub("", text)
    text = PUNCTUATION_PATTERN.sub("", text)
    text = re.sub(r"\s+", " ", text)
    return text.lower()


def function_name_indicates_bad(function_name):
    pattern = r"(?<![A-Za-z0-9])(?:bad(?:\d+)?|badSink(?:\d+)?|badSource(?:\d+)?)(?![A-Za-z0-9])"
    return bool(re.search(pattern, function_name or "", re.IGNORECASE))


def function_name_indicates_good(function_name):
    pattern = r"(?<![A-Za-z0-9])(?:good(?:\d+)?|goodG2B(?:\d+)?|goodB2G(?:\d+)?)(?![A-Za-z0-9])"
    return bool(re.search(pattern, function_name or "", re.IGNORECASE))


def extract_cwe_from_filename(filename):
    match = re.search(r"(CWE\d+)", filename)
    return match.group(1).replace("CWE", "") if match else ""


def assign_priority(severity, message, cwe):
    text = f"{severity} {message} {cwe}".lower()

    high_keywords = [
        "null pointer",
        "dereference",
        "use after free",
        "double free",
        "buffer overflow",
        "memory leak",
        "dead store",
    ]

    if severity.lower() == "error":
        return "HIGH"

    if any(keyword in text for keyword in high_keywords):
        return "HIGH"

    if severity.lower() == "warning":
        return "MEDIUM"

    return "LOW"


def label_from_priority(priority):
    return {
        "LOW": 0,
        "MEDIUM": 1,
        "HIGH": 2
    }.get(priority, 0)


def extract_juliet_cwe_family(path):
    for part in Path(path).parts:
        if part.startswith("CWE") and "_" in part:
            return part

    return ""


def infer_ground_truth(source_file, source_function, line_number=None):
    if function_name_indicates_bad(source_function):
        return "bad", 1, 0, "plist_source_function"

    if function_name_indicates_good(source_function):
        return "good", 0, 1, "plist_source_function"

    if line_number is None:
        return "unknown", 0, 0, "unknown"

    return infer_ground_truth_from_enclosing_function(source_file, line_number)


def infer_ground_truth_from_source_line(source_line_text):
    line_text = str(source_line_text or "").strip()
    if function_name_indicates_bad(line_text):
        return "bad", 1, 0, "enclosing_function"

    if function_name_indicates_good(line_text):
        return "good", 0, 1, "enclosing_function"

    return "unknown", 0, 0, "unknown"


def infer_ground_truth_from_enclosing_function(source_file, line_number):
    source_path = Path(source_file)

    if not source_path.exists() or not source_path.is_file():
        return "unknown", 0, 0, "unknown"

    try:
        lines = source_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except Exception:
        return "unknown", 0, 0, "unknown"

    function_signature_pattern = re.compile(
        r"^\s*(?:static\s+)?(?:void|int|char|short|long|float|double|bool|size_t|unsigned|signed|struct\s+[A-Za-z_][A-Za-z0-9_]*)\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^;]*\)\s*(\{)?\s*$"
    )

    current_function = ""
    function_start = 0
    brace_depth = 0
    pending_function = ""
    pending_start = 0

    for index, line in enumerate(lines, start=1):
        if not current_function:
            match = function_signature_pattern.match(line)
            if match:
                pending_function = match.group(1)
                pending_start = index
                if match.group(2):
                    current_function = pending_function
                    function_start = pending_start
                    brace_depth = line.count("{") - line.count("}")
                    pending_function = ""
                    pending_start = 0
                continue

            if pending_function:
                brace_depth += line.count("{") - line.count("}")
                if line.count("{") > 0:
                    current_function = pending_function
                    function_start = pending_start
                    pending_function = ""
                    pending_start = 0
                continue

        if current_function:
            brace_depth += line.count("{") - line.count("}")

            if function_start <= line_number <= index:
                if function_name_indicates_bad(current_function):
                    return "bad", 1, 0, "enclosing_function"

                if function_name_indicates_good(current_function):
                    return "good", 0, 1, "enclosing_function"

            if brace_depth <= 0:
                current_function = ""
                function_start = 0
                brace_depth = 0

    return "unknown", 0, 0, "unknown"


def extract_source_function_from_plist(plist_path, source_file, line_number, message):
    if plist_path is None:
        return "", False

    if not plist_path.exists() or not plist_path.is_file() or plist_path.stat().st_size == 0:
        return "", False

    try:
        report = plistlib.load(plist_path.open("rb"))
    except Exception:
        return "", False

    files = report.get("files", [])
    diagnostics = report.get("diagnostics", [])
    matched_source_file = choose_plist_source_file(source_file, files)

    matches = []
    normalized_text_message = normalize_message_text(message)

    for diagnostic in diagnostics:
        location = diagnostic.get("location", {})
        file_index = location.get("file")
        diag_file = ""

        if isinstance(file_index, int) and 0 <= file_index < len(files):
            diag_file = files[file_index]

        if matched_source_file and normalize_path_text(diag_file) != normalize_path_text(matched_source_file):
            continue

        diag_line = location.get("line")
        diag_description = normalize_message_text(diagnostic.get("description", ""))
        diag_context = str(diagnostic.get("issue_context", "")).strip()

        if diag_line != line_number:
            continue

        if diag_description == normalized_text_message or not normalized_text_message:
            matches.append(diagnostic)
            continue

        if diag_context and (function_name_indicates_bad(diag_context) or function_name_indicates_good(diag_context)):
            matches.append(diagnostic)

    if len(matches) != 1:
        return "", bool(matched_source_file)

    diag = matches[0]

    if diag.get("issue_context_kind") != "function":
        return "", True

    issue_context = str(diag.get("issue_context", "")).strip()
    return issue_context, True


def parse_txt_file(txt_file, plist_index):
    alerts = []

    cwe = extract_cwe_from_filename(txt_file.name)

    with open(txt_file, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    row_counter = 0

    for line in lines:
        # Example:
        # path/file.c:10:5: warning: message text
        match = re.search(r"(.+?):(\d+):\d+:\s+(warning|error|note):\s+(.+)", line)

        if match:
            file_path = match.group(1)
            line_number = match.group(2)
            severity = match.group(3)
            message = match.group(4).strip()

            if severity == "note":
                continue

            alert_id = message.split(":")[0][:60]
            cwe_family = extract_juliet_cwe_family(file_path)

            plist_path = resolve_matching_plist(plist_index, file_path)
            source_function, has_plist_match = extract_source_function_from_plist(
                plist_path,
                file_path,
                int(line_number),
                message,
            )

            ground_truth_status, is_bad_path, is_good_path, ground_truth_origin = infer_ground_truth(
                file_path,
                source_function,
                int(line_number),
            )

            juliet_case_id = normalize_case_id(Path(file_path).stem)
            annotation_source = f"{file_path}|{line_number}|{alert_id}|{cwe}|{severity}|{message}"
            annotation_id = f"clang-ann-{hashlib.sha1(annotation_source.encode('utf-8')).hexdigest()[:16]}"

            alerts.append({
                "annotation_id": annotation_id,
                "tool": "clang",
                "source_file": file_path,
                "line": line_number,
                "alert_id": alert_id,
                "cwe": cwe,
                "severity": severity,
                "message": message,
                "juliet_case_id": juliet_case_id,
                "juliet_cwe_family": cwe_family,
                "source_function": source_function,
                "is_bad_path": is_bad_path,
                "is_good_path": is_good_path,
                "ground_truth_status": ground_truth_status,
                "ground_truth_origin": ground_truth_origin,
                "raw_report_path": str(txt_file),
                "manual_priority": "",
                "annotation_reason": "",
                "has_plist_match": has_plist_match,
            })
            row_counter += 1

    return alerts


def build_plist_index():
    plist_index = {}

    for plist_file in RAW_OUTPUT_DIR.glob("*.plist"):
        if plist_file.stat().st_size == 0:
            continue

        try:
            report = plistlib.load(plist_file.open("rb"))
        except Exception:
            continue

        files = report.get("files", [])

        for source_file in files:
            plist_index[normalize_path_text(source_file)] = plist_file

    return plist_index


def resolve_matching_plist(plist_index, source_file):
    normalized_source = normalize_path_text(source_file)
    if not normalized_source:
        return None

    direct_match = plist_index.get(normalized_source)
    if direct_match:
        return direct_match

    suffix_matches = []
    for indexed_source, plist_file in plist_index.items():
        indexed_normalized = normalize_path_text(indexed_source)
        if not indexed_normalized:
            continue

        if normalized_source.endswith(indexed_normalized) or indexed_normalized.endswith(normalized_source):
            suffix_matches.append(plist_file)

    unique_matches = list(dict.fromkeys(suffix_matches))
    if len(unique_matches) == 1:
        return unique_matches[0]

    return None


def collect_annotation_statistics(df, plist_index):
    if df.empty:
        return {
            "alerts_with_plist_match": 0,
            "alerts_without_plist_match": 0,
            "alerts_with_source_function": 0,
            "alerts_classified_from_source_function": 0,
            "alerts_classified_from_enclosing_source_function": 0,
            "bad_count": 0,
            "good_count": 0,
            "unknown_count": 0,
            "unique_case_ids_before_corrected_normalization": 0,
            "unique_case_ids_after_corrected_normalization": 0,
        }

    alerts_with_plist_match = int(df["has_plist_match"].sum()) if "has_plist_match" in df.columns else 0
    alerts_without_plist_match = int((~df["has_plist_match"]).sum()) if "has_plist_match" in df.columns else 0
    alerts_with_source_function = int(df["source_function"].astype(str).str.len().gt(0).sum())

    classified_from_source_function = int((df["ground_truth_origin"] == "plist_source_function").sum()) if "ground_truth_origin" in df.columns else 0
    classified_from_enclosing_source_function = int((df["ground_truth_origin"] == "enclosing_function").sum()) if "ground_truth_origin" in df.columns else 0

    before_unique = int(df["source_file"].map(lambda value: Path(str(value)).stem).nunique())
    after_unique = int(df["juliet_case_id"].nunique())

    return {
        "alerts_with_plist_match": alerts_with_plist_match,
        "alerts_without_plist_match": alerts_without_plist_match,
        "alerts_with_source_function": alerts_with_source_function,
        "alerts_classified_from_source_function": classified_from_source_function,
        "alerts_classified_from_enclosing_source_function": classified_from_enclosing_source_function,
        "bad_count": int((df["ground_truth_status"] == "bad").sum()),
        "good_count": int((df["ground_truth_status"] == "good").sum()),
        "unknown_count": int((df["ground_truth_status"] == "unknown").sum()),
        "unique_case_ids_before_corrected_normalization": before_unique,
        "unique_case_ids_after_corrected_normalization": after_unique,
    }


def main():
    all_alerts = []

    if not RAW_OUTPUT_DIR.exists():
        print(f"Raw output folder not found: {RAW_OUTPUT_DIR}")
        return

    txt_files = list(RAW_OUTPUT_DIR.glob("*.txt"))
    plist_index = build_plist_index()
    source_files_scanned = len(txt_files)

    print(f"Found {len(txt_files)} Clang raw output files.")
    print(f"Found {len(plist_index)} source file entries in plist reports.")

    for txt_file in txt_files:
        alerts = parse_txt_file(txt_file, plist_index)
        all_alerts.extend(alerts)

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    df = pd.DataFrame(all_alerts)

    if df.empty:
        print("No Clang alerts found. Empty annotation dataset created.")
        df = pd.DataFrame(columns=[
            "annotation_id",
            "tool",
            "source_file",
            "line",
            "alert_id",
            "cwe",
            "severity",
            "message",
            "juliet_case_id",
            "juliet_cwe_family",
            "source_function",
            "is_bad_path",
            "is_good_path",
            "ground_truth_status",
            "raw_report_path",
            "manual_priority",
            "annotation_reason",
        ])

    before_dedup = len(df)
    dedup_subset = [
        "juliet_case_id",
        "source_file",
        "line",
        "alert_id",
        "cwe",
        "severity",
        "message",
    ]
    df = df.drop_duplicates(subset=dedup_subset, keep="first")
    after_dedup = len(df)

    stats = collect_annotation_statistics(df, plist_index)

    if not df.empty:
        print("\nJuliet case ID samples:")
        sample_df = df[["source_file", "juliet_case_id"]].drop_duplicates().head(30)
        for _, row in sample_df.iterrows():
            print(f"{row['source_file']} -> {row['juliet_case_id']}")

        print("\nMatching audit sample:")
        audit_cols = ["source_file", "line", "message", "source_function", "ground_truth_status", "ground_truth_origin"]
        for _, row in df[audit_cols].head(20).iterrows():
            print(
                f"{row['source_file']} | line {row['line']} | message={row['message']} | source_function={row['source_function']} | status={row['ground_truth_status']} | origin={row['ground_truth_origin']}"
            )

    output_columns = [
        "annotation_id",
        "tool",
        "source_file",
        "line",
        "alert_id",
        "cwe",
        "severity",
        "message",
        "juliet_case_id",
        "juliet_cwe_family",
        "source_function",
        "is_bad_path",
        "is_good_path",
        "ground_truth_status",
        "raw_report_path",
        "manual_priority",
        "annotation_reason",
    ]

    df = df.reindex(columns=output_columns + ["has_plist_match", "ground_truth_origin"])

    df.to_csv(OUTPUT_FILE, index=False, columns=output_columns)

    print(f"Clang annotation dataset created: {OUTPUT_FILE}")
    print(f"Number of source files scanned: {source_files_scanned}")
    print(f"Number of alerts generated: {before_dedup}")
    print(f"Rows before deduplication: {before_dedup}")
    print(f"Rows after deduplication: {after_dedup}")
    print(f"Duplicate rows removed: {before_dedup - after_dedup}")
    print(f"Unique source files: {df['source_file'].nunique() if not df.empty else 0}")
    print(f"Unique Juliet case IDs: {df['juliet_case_id'].nunique() if not df.empty else 0}")
    print(f"Unique alert IDs: {df['alert_id'].nunique() if not df.empty else 0}")
    print(f"alerts with plist match: {stats['alerts_with_plist_match']}")
    print(f"alerts without plist match: {stats['alerts_without_plist_match']}")
    print(f"alerts with source_function: {stats['alerts_with_source_function']}")
    print(f"alerts classified from source_function: {stats['alerts_classified_from_source_function']}")
    print(f"alerts classified from enclosing source function: {stats['alerts_classified_from_enclosing_source_function']}")
    print("\nCWE distribution:")
    if not df.empty:
        print(df["cwe"].value_counts())
    else:
        print(pd.Series(dtype=int))

    print("\nGround truth status counts:")
    if not df.empty:
        print(df["ground_truth_status"].value_counts(dropna=False))
    else:
        print(pd.Series(dtype=int))

    bad_count = int(df["is_bad_path"].sum()) if not df.empty else 0
    good_count = int(df["is_good_path"].sum()) if not df.empty else 0
    unknown_count = int((df["ground_truth_status"] == "unknown").sum()) if not df.empty else 0
    print(f"bad/good/unknown counts: bad={bad_count}, good={good_count}, unknown={unknown_count}")

    print("\nCorrected Juliet case ID stats:")
    print(
        f"unique case IDs before corrected normalization: {stats['unique_case_ids_before_corrected_normalization']}"
    )
    print(
        f"unique case IDs after corrected normalization: {stats['unique_case_ids_after_corrected_normalization']}"
    )

if __name__ == "__main__":
    main()