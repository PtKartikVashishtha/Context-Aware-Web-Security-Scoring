import csv
import gzip


OUR_FILE = (
    "data/processed/"
    "cve_level_owasp_2025_historical.csv"
)

EPSS_FILE = (
    "data/raw/epss/"
    "epss_scores-2025-12-31.csv.gz"
)


def load_our_cves():

    cves = set()

    with open(
        OUR_FILE,
        "r",
        encoding="utf-8",
        newline=""
    ) as f:

        reader = csv.DictReader(f)

        for row in reader:
            cves.add(row["cve_id"])

    return cves


def load_epss_cves():

    cves = set()

    with gzip.open(
        EPSS_FILE,
        "rt",
        encoding="utf-8",
        errors="replace"
    ) as f:

        reader = csv.reader(f)

        for row in reader:

            if not row:
                continue

            if row[0].startswith("#"):
                continue

            if row[0] == "cve":
                continue

            if len(row) >= 3:
                cves.add(row[0])

    return cves


def main():

    our_cves = load_our_cves()
    epss_cves = load_epss_cves()

    missing = sorted(
        our_cves - epss_cves
    )

    print("======================================")
    print("MISSING EPSS CVEs")
    print("======================================")

    print(
        f"Missing count: {len(missing)}"
    )

    print()

    for cve in missing:
        print(cve)


if __name__ == "__main__":
    main()