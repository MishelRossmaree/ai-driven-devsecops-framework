import os
import subprocess
from pathlib import Path

JULIET_C_PATH = Path("data/raw/alert_prioritizer/clang/C")
OUTPUT_DIR = Path("reports/alert_prioritizer/clang/raw_outputs")

SELECTED_CWES = [
    "CWE476_NULL_Pointer_Dereference",
    "CWE121_Stack_Based_Buffer_Overflow",
    "CWE122_Heap_Based_Buffer_Overflow",
    "CWE415_Double_Free",
    "CWE416_Use_After_Free",
]

MAX_FILES_PER_CWE = 20


def find_source_files():
    files = []

    for cwe in SELECTED_CWES:
        cwe_path = JULIET_C_PATH / "testcases" / cwe

        if not cwe_path.exists():
            print(f"Skipping missing folder: {cwe_path}")
            continue

        c_files = list(cwe_path.rglob("*.c"))
        cpp_files = list(cwe_path.rglob("*.cpp"))

        selected = (c_files + cpp_files)[:MAX_FILES_PER_CWE]

        for file in selected:
            files.append((cwe, file))

    return files


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
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    source_files = find_source_files()

    print(f"Total files selected for Clang scan: {len(source_files)}")

    for index, (cwe, file_path) in enumerate(source_files, start=1):
        safe_name = file_path.name.replace("/", "_")
        output_file = OUTPUT_DIR / f"{index}_{cwe}_{safe_name}.txt"

        print(f"[{index}/{len(source_files)}] Scanning: {file_path}")
        run_clang(file_path, output_file)

    print(f"Clang raw outputs saved in: {OUTPUT_DIR}")


if __name__ == "__main__":
    main()