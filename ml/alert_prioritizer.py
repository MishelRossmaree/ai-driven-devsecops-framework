import csv
import os
import xml.etree.ElementTree as ET

CPPCHECK_REPORT = "reports/cppcheck-report.xml"
OUTPUT_FILE = "reports/prioritised-alerts.csv"

IGNORED_ALERT_IDS = {
    "checkersReport"
}

IGNORED_SEVERITIES = {
    # Keep empty for now.
    # Later, if you want to remove information-only alerts:
    # "information"
}


def is_real_alert(alert_id, severity):
    if alert_id in IGNORED_ALERT_IDS:
        return False

    if severity in IGNORED_SEVERITIES:
        return False

    return True


def priority_from_alert(severity, cwe, alert_id, message):
    score = 0
    text = f"{severity} {cwe} {alert_id} {message}".lower()

    if severity == "error":
        score += 40
    elif severity == "warning":
        score += 25
    elif severity == "information":
        score += 5

    if cwe:
        score += 20

    high_risk_keywords = [
        "nullpointer",
        "null pointer",
        "buffer",
        "overflow",
        "gets",
        "strcpy",
        "strcat",
        "sprintf",
        "memcpy",
        "memory",
        "dereference",
        "use after free",
        "double free",
    ]

    if any(keyword in text for keyword in high_risk_keywords):
        score += 30

    if score >= 60:
        return "HIGH", score
    elif score >= 30:
        return "MEDIUM", score
    else:
        return "LOW", score


def parse_cppcheck_report():
    alerts = []

    if not os.path.exists(CPPCHECK_REPORT):
        print("Cppcheck report not found.")
        return alerts

    tree = ET.parse(CPPCHECK_REPORT)
    root = tree.getroot()

    for error in root.findall(".//error"):
        alert_id = error.get("id", "")
        severity = error.get("severity", "")
        message = error.get("msg", "")
        cwe = error.get("cwe", "")

        if not is_real_alert(alert_id, severity):
            continue

        location = error.find("location")
        file_name = location.get("file", "") if location is not None else ""
        line = location.get("line", "") if location is not None else ""

        priority, score = priority_from_alert(severity, cwe, alert_id, message)

        alerts.append({
            "priority": priority,
            "score": score,
            "tool": "Cppcheck",
            "file": file_name,
            "line": line,
            "alert_id": alert_id,
            "cwe": cwe,
            "severity": severity,
            "message": message,
        })

    return alerts


def write_prioritised_alerts(alerts):
    os.makedirs("reports", exist_ok=True)

    alerts = sorted(alerts, key=lambda x: x["score"], reverse=True)

    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as csvfile:
        fieldnames = [
            "priority",
            "score",
            "tool",
            "file",
            "line",
            "alert_id",
            "cwe",
            "severity",
            "message",
        ]

        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(alerts)

    print(f"Prioritised alerts generated: {OUTPUT_FILE}")


if __name__ == "__main__":
    alerts = parse_cppcheck_report()
    write_prioritised_alerts(alerts)

    print("===== Prioritised Alerts =====")
    if not alerts:
        print("No real alerts found.")
    else:
        for alert in alerts:
            cwe_text = f"CWE-{alert['cwe']}" if alert["cwe"] else "No CWE"
            print(
                f"{alert['priority']} | {alert['tool']} | "
                f"{alert['file']}:{alert['line']} | "
                f"{alert['alert_id']} | {cwe_text}"
            )