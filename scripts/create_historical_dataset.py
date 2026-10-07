from pathlib import Path
import csv
import gzip
import json
from datetime import datetime, timezone
from collections import Counter


NVD_FILE = Path(
    "data/raw/nvd/nvdcve-2.0-2025.json.gz"
)

INPUT_FILE = Path(
    "data/processed/cve_level_owasp_2025.csv"
)

OUTPUT_FILE = Path(
    "data/processed/cve_level_owasp_2025_historical.csv"
)

# Exact timestamp of our EPSS snapshot.
CUTOFF = datetime(
    2025,
    12,
    31,
    12,
    55,
    0,
    tzinfo=timezone.utc
)


def parse_nvd_timestamp(value):
    """
    Convert an NVD timestamp into a timezone-aware datetime.

    Examples:
        2025-01-01T14:15:23.590
        2025-01-01T14:15:23.590Z
    """

    if not value:
        return None

    value = value.replace("Z", "+00:00")

    dt = datetime.fromisoformat(value)

    # NVD timestamps without an explicit timezone are treated as UTC.
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    return dt


def load_nvd_metadata():
    """
    Load publication timestamp and vulnerability status for
    every CVE in the NVD 2025 feed.

    Returns:
        {
            "CVE-XXXX-YYYY": {
                "published": datetime(...),
                "status": "Analyzed"
            }
        }
    """

    print("Loading NVD publication timestamps and statuses...")

    with gzip.open(
        NVD_FILE,
        "rt",
        encoding="utf-8"
    ) as f:

        data = json.load(f)

    metadata = {}

    for item in data["vulnerabilities"]:

        cve = item["cve"]

        cve_id = cve["id"]
        published = cve.get("published")
        status = cve.get("vulnStatus", "")

        if published:

            metadata[cve_id] = {
                "published": parse_nvd_timestamp(published),
                "status": status,
            }

    print(
        f"NVD metadata loaded: "
        f"{len(metadata):,}"
    )

    return metadata


def main():

    metadata = load_nvd_metadata()

    print()
    print("Loading CVE-level OWASP dataset...")

    rows = []

    with INPUT_FILE.open(
        "r",
        encoding="utf-8",
        newline=""
    ) as f:

        reader = csv.DictReader(f)

        for row in reader:
            rows.append(row)

    print(
        f"Input CVEs: {len(rows):,}"
    )

    historical_rows = []
    future_rows = []
    missing_date = []

    status_counter = Counter()

    for row in rows:

        cve_id = row["cve_id"]

        record = metadata.get(cve_id)

        if record is None:
            missing_date.append(cve_id)
            continue

        published = record["published"]
        status = record["status"]

        if published is None:
            missing_date.append(cve_id)
            continue

        # -----------------------------------------
        # HISTORICAL CUTOFF
        # -----------------------------------------

        if published <= CUTOFF:

            row["published_timestamp"] = published.isoformat()
            row["published_date"] = published.date().isoformat()
            row["vuln_status"] = status

            historical_rows.append(row)

            status_counter[status] += 1

        else:

            future_rows.append(row)

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    if historical_rows:

        fieldnames = list(
            historical_rows[0].keys()
        )

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
            writer.writerows(historical_rows)

    print()
    print("======================================")
    print("HISTORICAL DATASET CREATED")
    print("======================================")

    print(
        f"Input CVEs                  : "
        f"{len(rows):,}"
    )

    print(
        f"Published by EPSS snapshot : "
        f"{len(historical_rows):,}"
    )

    print(
        f"Published after snapshot   : "
        f"{len(future_rows):,}"
    )

    print(
        f"Missing publication date   : "
        f"{len(missing_date):,}"
    )

    print()
    print("VULNERABILITY STATUS")
    print("--------------------------------------")

    for status, count in status_counter.most_common():

        label = status if status else "(empty)"

        print(
            f"{label:20} : {count:,}"
        )

    print()
    print("Exact cutoff:")
    print(
        CUTOFF.isoformat()
    )

    print()
    print(
        f"Saved to:\n{OUTPUT_FILE}"
    )


if __name__ == "__main__":
    main()