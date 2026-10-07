from pathlib import Path
import csv


MASTER_FILE = Path(
    "data/processed/vulnerability_master_2025.csv"
)

OWASP_MAP_FILE = Path(
    "data/processed/owasp_2025_cwe_map.csv"
)

OUTPUT_FILE = Path(
    "data/processed/cve_level_owasp_2025.csv"
)


def load_owasp_map():
    """
    Returns:

        CWE -> {
            owasp_category,
            owasp_name
        }
    """

    mapping = {}

    with OWASP_MAP_FILE.open(
        "r",
        encoding="utf-8",
        newline=""
    ) as f:

        reader = csv.DictReader(f)

        for row in reader:
            mapping[row["cwe"]] = {
                "owasp_category": row["owasp_category"],
                "owasp_name": row["owasp_name"],
            }

    return mapping


def split_values(value):
    """
    Convert:

        CWE-89;CWE-74

    into:

        ["CWE-89", "CWE-74"]
    """

    if not value:
        return []

    return [
        item.strip()
        for item in value.split(";")
        if item.strip()
    ]


def main():

    print("Loading OWASP 2025 CWE mapping...")

    owasp_map = load_owasp_map()

    print(
        f"Loaded {len(owasp_map)} CWE mappings."
    )

    print()
    print("Loading vulnerability master...")

    rows = []

    with MASTER_FILE.open(
        "r",
        encoding="utf-8",
        newline=""
    ) as f:

        reader = csv.DictReader(f)

        for row in reader:
            rows.append(row)

    print(
        f"Master CVEs loaded: {len(rows):,}"
    )

    output_rows = []

    skipped = 0

    for row in rows:

        cve_id = row["cve_id"]

        all_cwes = split_values(row["cwe"])

        # Keep only CWEs that belong to OWASP Top 10:2025.
        mapped_cwes = [
            cwe
            for cwe in all_cwes
            if cwe in owasp_map
        ]

        if not mapped_cwes:
            skipped += 1
            continue

        # ------------------------------------------------
        # PRIMARY CWE
        # ------------------------------------------------
        #
        # vulnerability_master_2025.csv was created by
        # our parser with NVD Primary CWE first.
        #
        # Therefore, the first mapped CWE is our
        # deterministic primary OWASP-relevant CWE.
        #
        primary_cwe = mapped_cwes[0]

        primary_info = owasp_map[primary_cwe]

        # ------------------------------------------------
        # ALL OWASP CATEGORIES
        # ------------------------------------------------

        all_categories = []

        for cwe in mapped_cwes:

            category = owasp_map[cwe]["owasp_category"]

            if category not in all_categories:
                all_categories.append(category)

        all_names = []

        for category in all_categories:

            # Find category name from first matching CWE.
            for cwe in mapped_cwes:

                info = owasp_map[cwe]

                if info["owasp_category"] == category:
                    all_names.append(info["owasp_name"])
                    break

        # ------------------------------------------------
        # OUTPUT
        # ------------------------------------------------

        output_rows.append([
            cve_id,
            primary_cwe,
            ";".join(all_cwes),
            ";".join(mapped_cwes),
            primary_info["owasp_category"],
            primary_info["owasp_name"],
            ";".join(all_categories),
            ";".join(all_names),
            row["cvss_base_score"],
            row["attack_vector"],
            row["attack_complexity"],
            row["privileges_required"],
            row["user_interaction"],
            row["exploit_available_evidence"],
        ])

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with OUTPUT_FILE.open(
        "w",
        encoding="utf-8",
        newline=""
    ) as f:

        writer = csv.writer(f)

        writer.writerow([
            "cve_id",
            "primary_cwe",
            "all_cwes",
            "mapped_owasp_cwes",
            "primary_owasp_category",
            "primary_owasp_name",
            "all_owasp_categories",
            "all_owasp_names",
            "cvss_base_score",
            "attack_vector",
            "attack_complexity",
            "privileges_required",
            "user_interaction",
            "exploit_available_evidence",
        ])

        writer.writerows(output_rows)

    # ------------------------------------------------
    # STATISTICS
    # ------------------------------------------------

    multi_cwe = 0
    multi_owasp = 0

    for row in output_rows:

        if ";" in row[2]:
            multi_cwe += 1

        if ";" in row[6]:
            multi_owasp += 1

    print()
    print("======================================")
    print("CVE-LEVEL DATASET CREATED")
    print("======================================")

    print(
        f"Input CVEs                  : "
        f"{len(rows):,}"
    )

    print(
        f"Output CVEs                 : "
        f"{len(output_rows):,}"
    )

    print(
        f"Skipped (no OWASP mapping)  : "
        f"{skipped:,}"
    )

    print(
        f"CVEs with multiple CWEs     : "
        f"{multi_cwe:,}"
    )

    print(
        f"CVEs spanning multiple OWASP "
        f"categories                 : {multi_owasp:,}"
    )

    print()
    print(f"Saved to:")
    print(OUTPUT_FILE)


if __name__ == "__main__":
    main()