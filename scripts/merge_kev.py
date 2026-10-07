from pathlib import Path
import csv
import json
from datetime import date


INPUT_CVE = Path(
    "data/processed/cve_level_owasp_2025_historical.csv"
)

INPUT_KEV = Path(
    "data/raw/kev/known_exploited_vulnerabilities.json"
)

OUTPUT = Path(
    "data/processed/cve_level_owasp_2025_historical_with_kev.csv"
)

# Historical KEV cutoff.
# KEV provides dateAdded at date granularity.
CUTOFF_DATE = date(2025, 12, 31)


def load_historical_kev():

    with INPUT_KEV.open(
        "r",
        encoding="utf-8"
    ) as f:

        data = json.load(f)

    kev_before_cutoff = set()
    kev_after_cutoff = set()

    for vulnerability in data.get(
        "vulnerabilities",
        []
    ):

        cve_id = vulnerability.get(
            "cveID",
            ""
        ).strip()

        date_added = vulnerability.get(
            "dateAdded",
            ""
        ).strip()

        if not cve_id or not date_added:
            continue

        added_date = date.fromisoformat(
            date_added
        )

        if added_date <= CUTOFF_DATE:
            kev_before_cutoff.add(cve_id)
        else:
            kev_after_cutoff.add(cve_id)

    return (
        kev_before_cutoff,
        kev_after_cutoff,
        data
    )


def main():

    print("Loading historical CISA KEV information...")

    (
        kev_before_cutoff,
        kev_after_cutoff,
        kev_data
    ) = load_historical_kev()

    print(
        f"Current KEV catalog version : "
        f"{kev_data.get('catalogVersion')}"
    )

    print(
        f"Current KEV entries         : "
        f"{len(kev_data.get('vulnerabilities', [])):,}"
    )

    print(
        f"KEV added by cutoff         : "
        f"{len(kev_before_cutoff):,}"
    )

    print(
        f"KEV added after cutoff      : "
        f"{len(kev_after_cutoff):,}"
    )

    print()
    print("Loading historical CVE dataset...")

    rows = []

    with INPUT_CVE.open(
        "r",
        encoding="utf-8",
        newline=""
    ) as f:

        reader = csv.DictReader(f)

        for row in reader:
            rows.append(row)

    print(
        f"Historical CVEs: {len(rows):,}"
    )

    matched = 0

    for row in rows:

        cve_id = row["cve_id"]

        if cve_id in kev_before_cutoff:

            row["known_exploitation"] = "1"
            matched += 1

        else:

            row["known_exploitation"] = "0"

    OUTPUT.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    fieldnames = list(rows[0].keys())

    # Avoid duplicate column if script is rerun.
    if "known_exploitation" not in fieldnames:
        fieldnames.append(
            "known_exploitation"
        )

    with OUTPUT.open(
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

    print()
    print("======================================")
    print("HISTORICAL KEV MERGE COMPLETE")
    print("======================================")

    print(
        f"Research CVEs             : "
        f"{len(rows):,}"
    )

    print(
        f"Known exploited by cutoff : "
        f"{matched:,}"
    )

    print(
        f"Not known exploited       : "
        f"{len(rows) - matched:,}"
    )

    print(
        f"Historical KEV rate       : "
        f"{matched / len(rows) * 100:.2f}%"
    )

    print()
    print(
        f"Saved to:\n{OUTPUT}"
    )


if __name__ == "__main__":
    main()