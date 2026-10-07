import csv
import gzip
import json
from collections import Counter
from datetime import datetime


NVD_FILE = "data/raw/nvd/nvdcve-2.0-2025.json.gz"

OUR_FILE = "data/processed/cve_level_owasp_2025_with_kev.csv"

EPSS_FILE = "data/raw/epss/epss_scores-2025-12-31.csv.gz"


SNAPSHOT_DATE = "2025-12-31"


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

            # Metadata line
            if row[0].startswith("#"):
                continue

            # Header
            if row[0] == "cve":
                continue

            if len(row) >= 3:
                cves.add(row[0])

    return cves


def main():

    print("Loading our CVEs...")
    our_cves = load_our_cves()

    print(
        f"Our CVEs: {len(our_cves):,}"
    )

    print()
    print("Loading EPSS snapshot...")
    epss_cves = load_epss_cves()

    print(
        f"EPSS scored CVEs: {len(epss_cves):,}"
    )

    missing = our_cves - epss_cves

    print()
    print(
        f"Missing EPSS: {len(missing):,}"
    )

    print()
    print("Loading NVD dates...")

    publication_dates = {}

    with gzip.open(
        NVD_FILE,
        "rt",
        encoding="utf-8"
    ) as f:

        data = json.load(f)

    for item in data["vulnerabilities"]:

        cve = item["cve"]

        cve_id = cve["id"]

        if cve_id in missing:

            published = cve.get(
                "published",
                ""
            )

            publication_dates[cve_id] = published

    # -----------------------------------------
    # CLASSIFY MISSING CVEs
    # -----------------------------------------

    published_before_snapshot = []
    published_after_snapshot = []
    invalid_dates = []

    snapshot = datetime.fromisoformat(
        SNAPSHOT_DATE
    )

    for cve_id in missing:

        date_string = publication_dates.get(
            cve_id,
            ""
        )

        if not date_string:

            invalid_dates.append(cve_id)
            continue

        try:

            date_string = date_string.replace(
                "Z",
                "+00:00"
            )

            published = datetime.fromisoformat(
                date_string
            )

            # Remove timezone for comparison.
            published_date = published.replace(
                tzinfo=None
            )

            if published_date.date() <= snapshot.date():
                published_before_snapshot.append(cve_id)
            else:
                published_after_snapshot.append(cve_id)

        except ValueError:

            invalid_dates.append(cve_id)

    # -----------------------------------------
    # RESULTS
    # -----------------------------------------

    print()
    print("======================================")
    print("MISSING EPSS ANALYSIS")
    print("======================================")

    print(
        f"Missing EPSS total              : "
        f"{len(missing):,}"
    )

    print(
        f"Published by 2025-12-31         : "
        f"{len(published_before_snapshot):,}"
    )

    print(
        f"Published after 2025-12-31      : "
        f"{len(published_after_snapshot):,}"
    )

    print(
        f"Missing/invalid publication date : "
        f"{len(invalid_dates):,}"
    )

    # -----------------------------------------
    # EXAMPLES
    # -----------------------------------------

    print()
    print("Examples published BEFORE snapshot:")
    print("--------------------------------------")

    for cve in sorted(
        published_before_snapshot
    )[:15]:

        print(
            cve,
            "→",
            publication_dates.get(cve)
        )

    print()
    print("Examples published AFTER snapshot:")
    print("--------------------------------------")

    for cve in sorted(
        published_after_snapshot
    )[:15]:

        print(
            cve,
            "→",
            publication_dates.get(cve)
        )


if __name__ == "__main__":
    main()