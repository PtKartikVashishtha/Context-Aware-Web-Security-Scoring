from pathlib import Path
import csv
import gzip
import json


NVD_FILE = Path("data/raw/nvd/nvdcve-2.0-2025.json.gz")
OWASP_MAP_FILE = Path("data/processed/owasp_2025_cwe_map.csv")

OUTPUT_MASTER = Path("data/processed/vulnerability_master_2025.csv")
OUTPUT_OWASP = Path("data/processed/owasp_vulnerabilities_2025.csv")


def load_owasp_map():
    """
    Loads:

        CWE -> OWASP 2025 category/name
    """

    mapping = {}

    with OWASP_MAP_FILE.open(
        "r",
        encoding="utf-8",
        newline=""
    ) as f:

        reader = csv.DictReader(f)

        for row in reader:
            cwe = row["cwe"]

            mapping[cwe] = {
                "owasp_category": row["owasp_category"],
                "owasp_name": row["owasp_name"],
            }

    return mapping


def extract_cwes(cve):
    """
    Extract all unique CWE IDs from the NVD weaknesses section.
    Prefer the NVD primary weakness when available, but keep
    other reported CWEs because a CVE can have multiple CWE
    descriptions.
    """

    primary = []
    secondary = []

    for weakness in cve.get("weaknesses", []):

        source = weakness.get("source", "")
        weakness_type = weakness.get("type", "")

        target = primary if (
            source == "nvd@nist.gov"
            or weakness_type == "Primary"
        ) else secondary

        for description in weakness.get("description", []):

            value = description.get("value", "")

            if value.startswith("CWE-"):
                target.append(value)

    # Primary first, then secondary.
    ordered = []

    for cwe in primary + secondary:
        if cwe not in ordered:
            ordered.append(cwe)

    return ordered


def select_cvss31(cve):
    """
    Select CVSS v3.1 assessment using this priority:

        1. NVD Primary
        2. CNA Primary
        3. Any available v3.1

    Returns None if no CVSS v3.1 exists.
    """

    metrics = cve.get("metrics", {})
    assessments = metrics.get("cvssMetricV31", [])

    if not assessments:
        return None

    # 1. NVD primary
    for metric in assessments:
        if (
            metric.get("source") == "nvd@nist.gov"
            and metric.get("type") == "Primary"
        ):
            return metric

    # 2. CNA primary
    for metric in assessments:
        if metric.get("type") == "Primary":
            return metric

    # 3. Any v3.1
    return assessments[0]


def has_exploit_reference(cve):
    """
    Indicates whether NVD contains a reference explicitly tagged
    as an exploit.

    Important:
        1 = exploit evidence/reference exists
        0 = no exploit-tagged reference found

    This does NOT mean 'proven no exploit' when the value is 0.
    """

    for reference in cve.get("references", []):

        tags = reference.get("tags", [])

        if any(tag.lower() == "exploit" for tag in tags):
            return 1

    return 0


def main():

    print("Loading OWASP Top 10:2025 CWE mapping...")

    owasp_map = load_owasp_map()

    print(f"Loaded {len(owasp_map)} CWE mappings.")

    print()
    print("Loading NVD 2025...")

    with gzip.open(
        NVD_FILE,
        "rt",
        encoding="utf-8"
    ) as f:

        nvd = json.load(f)

    vulnerabilities = nvd["vulnerabilities"]

    print(f"NVD records: {len(vulnerabilities):,}")

    master_rows = []
    owasp_rows = []

    stats = {
        "total": 0,
        "cwe": 0,
        "cvss31": 0,
        "owasp": 0,
        "exploit_reference": 0,
    }

    for item in vulnerabilities:

        stats["total"] += 1

        cve = item["cve"]

        cve_id = cve.get("id", "")

        cwes = extract_cwes(cve)

        if cwes:
            stats["cwe"] += 1

        cvss_metric = select_cvss31(cve)

        if cvss_metric is None:
            continue

        stats["cvss31"] += 1

        cvss = cvss_metric["cvssData"]

        # Find only CWEs that belong to OWASP Top 10:2025.
        mapped = [
            cwe
            for cwe in cwes
            if cwe in owasp_map
        ]

        if not mapped:
            continue

        stats["owasp"] += 1

        exploit_reference = has_exploit_reference(cve)

        if exploit_reference:
            stats["exploit_reference"] += 1

        # -----------------------------
        # MASTER ROW
        # -----------------------------

        master_rows.append([
            cve_id,
            ";".join(cwes),
            cvss.get("baseScore"),
            cvss.get("attackVector"),
            cvss.get("attackComplexity"),
            cvss.get("privilegesRequired"),
            cvss.get("userInteraction"),
            exploit_reference,
        ])

        # -----------------------------
        # OWASP-SPECIFIC ROWS
        # -----------------------------

        for cwe in mapped:

            category = owasp_map[cwe]

            owasp_rows.append([
                cve_id,
                category["owasp_category"],
                category["owasp_name"],
                cwe,
                cvss.get("baseScore"),
                cvss.get("attackVector"),
                cvss.get("attackComplexity"),
                cvss.get("privilegesRequired"),
                cvss.get("userInteraction"),
                exploit_reference,
            ])

    # --------------------------------
    # WRITE MASTER DATASET
    # --------------------------------

    OUTPUT_MASTER.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with OUTPUT_MASTER.open(
        "w",
        encoding="utf-8",
        newline=""
    ) as f:

        writer = csv.writer(f)

        writer.writerow([
            "cve_id",
            "cwe",
            "cvss_base_score",
            "attack_vector",
            "attack_complexity",
            "privileges_required",
            "user_interaction",
            "exploit_available_evidence",
        ])

        writer.writerows(master_rows)

    # --------------------------------
    # WRITE OWASP DATASET
    # --------------------------------

    with OUTPUT_OWASP.open(
        "w",
        encoding="utf-8",
        newline=""
    ) as f:

        writer = csv.writer(f)

        writer.writerow([
            "cve_id",
            "owasp_category",
            "owasp_name",
            "cwe",
            "cvss_base_score",
            "attack_vector",
            "attack_complexity",
            "privileges_required",
            "user_interaction",
            "exploit_available_evidence",
        ])

        writer.writerows(owasp_rows)

    # --------------------------------
    # PRINT RESULTS
    # --------------------------------

    print()
    print("======================================")
    print("NVD PARSING COMPLETE")
    print("======================================")

    print(f"Total NVD CVEs               : {stats['total']:,}")
    print(f"CVEs with CWE                : {stats['cwe']:,}")
    print(f"CVEs with CVSS v3.1          : {stats['cvss31']:,}")
    print(f"OWASP 2025 matched CVEs      : {stats['owasp']:,}")
    print(f"Exploit-tagged references    : {stats['exploit_reference']:,}")

    print()
    print(f"Master dataset:")
    print(f"  {OUTPUT_MASTER}")

    print()
    print(f"OWASP dataset:")
    print(f"  {OUTPUT_OWASP}")


if __name__ == "__main__":
    main()