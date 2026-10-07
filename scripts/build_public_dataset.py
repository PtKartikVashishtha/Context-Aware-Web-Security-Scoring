from pathlib import Path
import csv


INPUT_CVE = Path(
    "data/processed/cve_level_owasp_2025_historical_with_kev.csv"
)

INPUT_EPSS = Path(
    "data/processed/epss_2025_for_historical_cves.csv"
)

OUTPUT = Path(
    "data/processed/public_dataset_v1.csv"
)


def load_epss():

    epss = {}

    with INPUT_EPSS.open(
        "r",
        encoding="utf-8",
        newline=""
    ) as f:

        reader = csv.DictReader(f)

        for row in reader:

            cve_id = row["cve_id"].strip()

            if not cve_id:
                continue

            epss[cve_id] = {
                "epss": row["epss"],
                "epss_percentile": row["epss_percentile"],
                "epss_snapshot_date": row[
                    "epss_snapshot_date"
                ],
                "epss_model_version": row[
                    "epss_model_version"
                ],
            }

    return epss


def main():

    print("Loading EPSS data...")

    epss = load_epss()

    print(
        f"EPSS records loaded: {len(epss):,}"
    )

    print()
    print("Loading corrected historical CVE dataset...")

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
    missing = 0

    for row in rows:

        cve_id = row["cve_id"]

        if cve_id in epss:

            record = epss[cve_id]

            row["epss"] = record["epss"]
            row["epss_percentile"] = record[
                "epss_percentile"
            ]
            row["epss_snapshot_date"] = record[
                "epss_snapshot_date"
            ]
            row["epss_model_version"] = record[
                "epss_model_version"
            ]
            row["epss_available"] = "1"

            matched += 1

        else:

            row["epss"] = ""
            row["epss_percentile"] = ""
            row["epss_snapshot_date"] = ""
            row["epss_model_version"] = ""
            row["epss_available"] = "0"

            missing += 1

    # -----------------------------------------
    # WRITE FINAL DATASET
    # -----------------------------------------

    OUTPUT.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    fieldnames = list(rows[0].keys())

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

    # -----------------------------------------
    # SUMMARY
    # -----------------------------------------

    print()
    print("======================================")
    print("PUBLIC DATASET V1 CREATED")
    print("======================================")

    print(
        f"Total CVEs             : {len(rows):,}"
    )

    print(
        f"KEV=1                 : "
        f"{sum(row['known_exploitation'] == '1' for row in rows):,}"
    )

    print(
        f"KEV=0                 : "
        f"{sum(row['known_exploitation'] == '0' for row in rows):,}"
    )

    print(
        f"EPSS matched          : {matched:,}"
    )

    print(
        f"EPSS missing          : {missing:,}"
    )

    print(
        f"EPSS coverage         : "
        f"{matched / len(rows) * 100:.2f}%"
    )

    print()
    print(f"Saved to:")
    print(OUTPUT)


if __name__ == "__main__":
    main()