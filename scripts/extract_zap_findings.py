import csv
import json
from pathlib import Path


# ---------------------------------------------------------
# Paths
# ---------------------------------------------------------
INPUT_FILE = Path("data/raw/zap/juice_shop_full_scan.json")
OUTPUT_FILE = Path("data/processed/zap_findings.csv")


# ---------------------------------------------------------
# ZAP risk/confidence mappings
# ---------------------------------------------------------
RISK_MAP = {
    "0": "Informational",
    "1": "Low",
    "2": "Medium",
    "3": "High",
    "4": "Critical",
}

CONFIDENCE_MAP = {
    "0": "False Positive",
    "1": "Low",
    "2": "Medium",
    "3": "High",
    "4": "Confirmed",
}


# ---------------------------------------------------------
# Main
# ---------------------------------------------------------
def main():
    if not INPUT_FILE.exists():
        raise FileNotFoundError(
            f"ZAP report not found:\n{INPUT_FILE.resolve()}"
        )

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    # Load ZAP JSON
    with INPUT_FILE.open("r", encoding="utf-8") as f:
        report = json.load(f)

    rows = []

    # ZAP JSON normally contains a "site" array
    sites = report.get("site", [])

    for site in sites:
        site_name = site.get("@name", "")
        alerts = site.get("alerts", [])

        for alert in alerts:
            plugin_id = str(
                alert.get("pluginid")
                or alert.get("pluginId")
                or ""
            )

            alert_name = (
                alert.get("alert")
                or alert.get("name")
                or ""
            )

            risk_code = str(alert.get("riskcode", ""))
            confidence_code = str(alert.get("confidence", ""))

            risk = RISK_MAP.get(risk_code, risk_code)
            confidence = CONFIDENCE_MAP.get(
                confidence_code,
                confidence_code
            )

            cwe_id = str(alert.get("cweid", ""))
            wasc_id = str(alert.get("wascid", ""))

            description = alert.get("desc", "")
            solution = alert.get("solution", "")
            reference = alert.get("reference", "")

            instances = alert.get("instances", [])

            # -------------------------------------------------
            # Keep one row per actual ZAP finding instance
            # -------------------------------------------------
            if instances:
                for index, instance in enumerate(instances, start=1):

                    rows.append({
                        "finding_id": f"{plugin_id}-{index}",
                        "site": site_name,
                        "plugin_id": plugin_id,
                        "alert_name": alert_name,
                        "risk_code": risk_code,
                        "risk": risk,
                        "confidence_code": confidence_code,
                        "confidence": confidence,
                        "url": instance.get("uri", ""),
                        "method": instance.get("method", ""),
                        "parameter": instance.get("param", ""),
                        "attack": instance.get("attack", ""),
                        "evidence": instance.get("evidence", ""),
                        "other_info": instance.get(
                            "otherinfo",
                            ""
                        ),
                        "cwe_id": cwe_id,
                        "wasc_id": wasc_id,
                        "description": description,
                        "solution": solution,
                        "reference": reference,
                    })

            # -------------------------------------------------
            # Fallback if alert has no instances
            # -------------------------------------------------
            else:
                rows.append({
                    "finding_id": f"{plugin_id}-1",
                    "site": site_name,
                    "plugin_id": plugin_id,
                    "alert_name": alert_name,
                    "risk_code": risk_code,
                    "risk": risk,
                    "confidence_code": confidence_code,
                    "confidence": confidence,
                    "url": "",
                    "method": "",
                    "parameter": "",
                    "attack": "",
                    "evidence": "",
                    "other_info": "",
                    "cwe_id": cwe_id,
                    "wasc_id": wasc_id,
                    "description": description,
                    "solution": solution,
                    "reference": reference,
                })

    # ---------------------------------------------------------
    # CSV columns
    # ---------------------------------------------------------
    fieldnames = [
        "finding_id",
        "site",
        "plugin_id",
        "alert_name",
        "risk_code",
        "risk",
        "confidence_code",
        "confidence",
        "url",
        "method",
        "parameter",
        "attack",
        "evidence",
        "other_info",
        "cwe_id",
        "wasc_id",
        "description",
        "solution",
        "reference",
    ]

    # ---------------------------------------------------------
    # Write CSV
    # ---------------------------------------------------------
    with OUTPUT_FILE.open(
        "w",
        encoding="utf-8",
        newline=""
    ) as f:

        writer = csv.DictWriter(
            f,
            fieldnames=fieldnames
        )

        writer.writeheader()
        writer.writerows(rows)

    # ---------------------------------------------------------
    # Summary
    # ---------------------------------------------------------
    alert_summary = {}

    for row in rows:
        alert_name = row["alert_name"]
        alert_summary[alert_name] = (
            alert_summary.get(alert_name, 0) + 1
        )

    print("=" * 60)
    print("ZAP FINDING EXTRACTION COMPLETE")
    print("=" * 60)

    print(f"Input file : {INPUT_FILE}")
    print(f"Output file: {OUTPUT_FILE}")
    print(f"Sites      : {len(sites)}")
    print(f"Findings   : {len(rows)}")

    print("\nAlert summary:")
    print("-" * 60)

    for alert_name, count in sorted(
        alert_summary.items(),
        key=lambda x: (-x[1], x[0])
    ):
        print(f"{count:>5}  {alert_name}")

    print("\nDone.")


if __name__ == "__main__":
    main()