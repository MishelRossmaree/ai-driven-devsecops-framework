import os
import random
import re
import subprocess
import shutil
from pathlib import Path

JULIET_C_PATH = Path("data/raw/alert_prioritizer/clang/C")
OUTPUT_DIR = Path("data/intermediate/alert_prioritizer/clang/raw_outputs")
SELECTED_CASES_PER_CWE = 200
SEED = 42

SELECTED_CWES = [
    "CWE476_NULL_Pointer_Dereference",
    "CWE121_Stack_Based_Buffer_Overflow",
    "CWE122_Heap_Based_Buffer_Overflow",
    "CWE415_Double_Free",
    "CWE416_Use_After_Free",
]

CASE_SUFFIX_PATTERN = re.compile(r"_(?:bad|goodG2B|goodB2G|good|\d+[a-z]?)$")


def normalize_case_id(stem):
    current = stem

    while True:
        updated = CASE_SUFFIX_PATTERN.sub("", current)

        if updated == current:
            return current

        current = updated


def select_case_groups(cwe_path):
    grouped_files = {}

    c_files = list(cwe_path.rglob("*.c"))
    cpp_files = list(cwe_path.rglob("*.cpp"))

    for file_path in c_files + cpp_files:
        case_id = normalize_case_id(file_path.stem)
        grouped_files.setdefault(case_id, []).append(file_path)

    group_ids = sorted(grouped_files)
    target_count = min(SELECTED_CASES_PER_CWE, len(group_ids))

    if target_count == 0:
        return [], grouped_files, []

    rng = random.Random(SEED)
    selected_group_ids = sorted(rng.sample(group_ids, target_count))

    selected_files = []

    for group_id in selected_group_ids:
        selected_files.extend(sorted(grouped_files[group_id]))

    return selected_group_ids, grouped_files, selected_files


def find_source_files():
    files = []
    case_counts = {}

    for cwe in SELECTED_CWES:
        cwe_path = JULIET_C_PATH / "testcases" / cwe

        if not cwe_path.exists():
            print(f"Skipping missing folder: {cwe_path}")
            continue

        selected_group_ids, grouped_files, selected = select_case_groups(cwe_path)
        case_counts[cwe] = len(selected_group_ids)

        print(
            f"Selected complete Juliet cases for {cwe}: {len(selected_group_ids)} "
            f"of {len(grouped_files)} available"
        )

        for file in selected:
            files.append((cwe, file))

    return files, case_counts


def run_clang(file_path, output_file):
    plist_output = OUTPUT_DIR / f"{file_path.stem}.plist"

    command = [
        "clang",
        "--analyze",
        "-Xanalyzer",
        "-analyzer-output=plist",
        "-o",
        str(plist_output),
        "-I",
        str(JULIET_C_PATH / "testcasesupport"),
        str(file_path),
    ]

    with open(output_file, "w", encoding="utf-8") as out:
        subprocess.run(
            command,
            stdout=out,
            stderr=out,
            text=True
        )

def main():
    if OUTPUT_DIR.exists():
        for child in OUTPUT_DIR.iterdir():
            if child.is_file() or child.is_symlink():
                child.unlink()
            elif child.is_dir():
                shutil.rmtree(child)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    source_files, case_counts = find_source_files()

    print(f"Total files selected for Clang scan: {len(source_files)}")
    print("Selected case count per CWE:")

    for cwe in SELECTED_CWES:
        if cwe in case_counts:
            print(f"- {cwe}: {case_counts[cwe]}")

    for index, (cwe, file_path) in enumerate(source_files, start=1):
        safe_name = file_path.name.replace("/", "_")
        output_file = OUTPUT_DIR / f"{index}_{cwe}_{safe_name}.txt"

        print(f"[{index}/{len(source_files)}] Scanning: {file_path}")
        run_clang(file_path, output_file)

    print(f"Clang raw outputs saved in: {OUTPUT_DIR}")


if __name__ == "__main__":
    main()