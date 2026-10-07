import csv
from collections import Counter


FILE = "data/processed/owasp_vulnerabilities_2025.csv"


def main():
    rows = []

    with open(FILE, "r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)

        for row in reader:
            rows.append(row)

    print("======================================")
    print("OWASP DATASET PROFILE")
    print("======================================")

    print(f"Total rows                  : {len(rows):,}")

    unique_cves = set(row["cve_id"] for row in rows)

    print(f"Unique CVEs                 : {len(unique_cves):,}")

    print()

    # ----------------------------------
    # OWASP CATEGORY DISTRIBUTION
    # ----------------------------------

    category_counts = Counter(
        row["owasp_category"]
        for row in rows
    )

    print("OWASP CATEGORY DISTRIBUTION")
    print("--------------------------------------")

    for category in sorted(category_counts):
        print(
            f"{category:8} : "
            f"{category_counts[category]:,}"
        )

    # ----------------------------------
    # CWE DISTRIBUTION
    # ----------------------------------

    cwe_counts = Counter(
        row["cwe"]
        for row in rows
    )

    print()
    print("Unique CWEs represented        :", len(cwe_counts))

    print()
    print("TOP 20 CWEs")
    print("--------------------------------------")

    for cwe, count in cwe_counts.most_common(20):
        print(f"{cwe:10} : {count:,}")

    # ----------------------------------
    # CVSS DISTRIBUTION
    # ----------------------------------

    scores = []

    for row in rows:
        if row["cvss_base_score"]:
            scores.append(float(row["cvss_base_score"]))

    print()
    print("CVSS STATISTICS")
    print("--------------------------------------")

    if scores:
        print(f"Minimum CVSS : {min(scores):.1f}")
        print(f"Maximum CVSS : {max(scores):.1f}")
        print(f"Average CVSS : {sum(scores) / len(scores):.2f}")

    # ----------------------------------
    # EXPLOIT REFERENCE
    # ----------------------------------

    exploit_count = sum(
        row["exploit_available_evidence"] == "1"
        for row in rows
    )

    print()
    print("EXPLOIT REFERENCE")
    print("--------------------------------------")

    print(f"With exploit-tagged reference : {exploit_count:,}")
    print(
        f"Without exploit-tagged reference : "
        f"{len(rows) - exploit_count:,}"
    )

    # ----------------------------------
    # CVE MULTIPLE-CWE CHECK
    # ----------------------------------

    cve_frequency = Counter(
        row["cve_id"]
        for row in rows
    )

    multi_cwe = {
        cve: count
        for cve, count in cve_frequency.items()
        if count > 1
    }

    print()
    print("MULTIPLE CWE CHECK")
    print("--------------------------------------")

    print(
        f"CVEs with multiple OWASP mappings : "
        f"{len(multi_cwe):,}"
    )

    print()
    print("Example multi-mapped CVEs:")

    for cve, count in list(multi_cwe.items())[:10]:
        print(f"  {cve} -> {count} rows")

    print()
    print("======================================")
    print("PROFILE COMPLETE")
    print("======================================")


if __name__ == "__main__":
    main()