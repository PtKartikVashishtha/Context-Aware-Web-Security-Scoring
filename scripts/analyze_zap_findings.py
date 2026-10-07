import csv
from collections import Counter
from pathlib import Path


INPUT_FILE = Path(
    "data/processed/zap_findings_owasp_2025.csv"
)


def main():
    if not INPUT_FILE.exists():
        raise FileNotFoundError(
            f"File not found: {INPUT_FILE.resolve()}"
        )

    with INPUT_FILE.open(
        "r",
        encoding="utf-8-sig",
        newline=""
    ) as f:
        rows = list(csv.DictReader(f))

    print("=" * 70)
    print("ZAP FINDING ANALYSIS")
    print("=" * 70)

    print(f"\nTotal rows: {len(rows)}")

    # ---------------------------------------------------------
    # CWE distribution
    # ---------------------------------------------------------

    cwe_counts = Counter()

    for row in rows:
        cwe = row.get("normalized_cwe", "").strip()

        if cwe:
            cwe_counts[cwe] += 1

    print("\nCWE distribution:")
    print("-" * 70)

    for cwe, count in cwe_counts.most_common():
        print(f"{count:>5}  {cwe}")

    # ---------------------------------------------------------
    # OWASP distribution
    # ---------------------------------------------------------

    owasp_counts = Counter()

    for row in rows:
        category = row.get(
            "owasp_category",
            ""
        ).strip()

        if category:
            owasp_counts[category] += 1

    print("\nOWASP Top 10:2025 distribution:")
    print("-" * 70)

    for category, count in sorted(
        owasp_counts.items()
    ):
        print(f"{count:>5}  {category}")

    # ---------------------------------------------------------
    # Unmapped CWEs
    # ---------------------------------------------------------

    unmapped_cwes = Counter()

    for row in rows:
        if row.get("owasp_mapping_status") == "NO_OWASP_MAPPING":

            cwe = row.get(
                "normalized_cwe",
                ""
            ).strip()

            if cwe:
                unmapped_cwes[cwe] += 1

    print("\nCWE values without OWASP 2025 mapping:")
    print("-" * 70)

    for cwe, count in unmapped_cwes.most_common():
        print(f"{count:>5}  {cwe}")

    # ---------------------------------------------------------
    # Findings without CWE
    # ---------------------------------------------------------

    no_cwe = [
        row
        for row in rows
        if row.get("owasp_mapping_status") == "NO_CWE"
    ]

    print("\nFindings without CWE:")
    print("-" * 70)

    seen = set()

    for row in no_cwe:
        key = (
            row.get("plugin_id", ""),
            row.get("alert_name", "")
        )

        if key not in seen:
            seen.add(key)

            print(
                f"{row.get('plugin_id', '')}  "
                f"{row.get('alert_name', '')}"
            )

    print("\nDone.")


if __name__ == "__main__":
    main()