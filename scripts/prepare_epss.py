from pathlib import Path
import csv
import gzip


OUR_DATASET = Path(
    "data/processed/cve_level_owasp_2025_historical.csv"
)

EPSS_FILE = Path(
    "data/raw/epss/epss_scores-2025-12-31.csv.gz"
)

OUTPUT = Path(
    "data/processed/epss_2025_for_historical_cves.csv"
)

SNAPSHOT_DATE = "2025-12-31"
MODEL_VERSION = "v2025.03.14"


def load_our_cves():

    cves = set()

    with OUR_DATASET.open(
        "r",
        encoding="utf-8",
        newline=""
    ) as f:

        reader = csv.DictReader(f)

        for row in reader:

            cve_id = row["cve_id"].strip()

            if cve_id:
                cves.add(cve_id)

    return cves


def main():

    our_cves = load_our_cves()

    print(
        f"Our historical CVEs: "
        f"{len(our_cves):,}"
    )

    matched = 0
    seen = set()

    OUTPUT.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with gzip.open(
        EPSS_FILE,
        "rt",
        encoding="utf-8",
        errors="replace"
    ) as f:

        reader = csv.reader(f)

        with OUTPUT.open(
            "w",
            encoding="utf-8",
            newline=""
        ) as out:

            writer = csv.writer(out)

            writer.writerow([
                "cve_id",
                "epss",
                "epss_percentile",
                "epss_snapshot_date",
                "epss_model_version",
            ])

            for row in reader:

                if not row:
                    continue

                if row[0].startswith("#"):
                    continue

                if row[0] == "cve":
                    continue

                if len(row) < 3:
                    continue

                cve_id = row[0].strip()

                if cve_id not in our_cves:
                    continue

                if cve_id in seen:
                    continue

                seen.add(cve_id)

                writer.writerow([
                    cve_id,
                    row[1],
                    row[2],
                    SNAPSHOT_DATE,
                    MODEL_VERSION,
                ])

                matched += 1

    missing = our_cves - seen

    print()
    print("======================================")
    print("EPSS HISTORICAL MATCH")
    print("======================================")

    print(
        f"Historical CVEs : {len(our_cves):,}"
    )

    print(
        f"EPSS matched    : {matched:,}"
    )

    print(
        f"EPSS missing    : {len(missing):,}"
    )

    print()
    print(f"Saved to: {OUTPUT}")


if __name__ == "__main__":
    main()