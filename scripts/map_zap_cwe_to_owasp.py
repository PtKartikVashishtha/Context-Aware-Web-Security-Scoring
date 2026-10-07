import csv
import re
from pathlib import Path


# =========================================================
# FILE PATHS
# =========================================================

INPUT_FILE = Path(
    "data/processed/zap_findings_unique.csv"
)

OWASP_MAP_FILE = Path(
    "data/processed/owasp_2025_cwe_map.csv"
)

OUTPUT_FILE = Path(
    "data/processed/zap_findings_unique_owasp_2025.csv"
)


# =========================================================
# HELPER FUNCTIONS
# =========================================================

def normalize_cwe(value: str) -> str:
    """
    Convert different CWE representations into:

        CWE-79
        CWE-89
        CWE-530

    Examples:
        79      -> CWE-79
        CWE-79 -> CWE-79
        cwe-79 -> CWE-79
        0       -> ""
        -1      -> ""
    """

    if value is None:
        return ""

    value = str(value).strip()

    if not value:
        return ""

    match = re.search(r"(\d+)", value)

    if not match:
        return ""

    number = int(match.group(1))

    if number == 0:
        return ""

    return f"CWE-{number}"


def find_column(fieldnames, candidates):
    """
    Locate a column despite small naming differences.
    """

    normalized = {
        str(name).strip().lower(): name
        for name in fieldnames
    }

    for candidate in candidates:
        candidate = candidate.strip().lower()

        if candidate in normalized:
            return normalized[candidate]

    return None


# =========================================================
# MAIN
# =========================================================

def main():

    # -----------------------------------------------------
    # Check files
    # -----------------------------------------------------

    if not INPUT_FILE.exists():
        raise FileNotFoundError(
            f"\nInput file not found:\n"
            f"{INPUT_FILE.resolve()}"
        )

    if not OWASP_MAP_FILE.exists():
        raise FileNotFoundError(
            f"\nOWASP mapping file not found:\n"
            f"{OWASP_MAP_FILE.resolve()}"
        )

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    # =====================================================
    # LOAD ZAP DATA
    # =====================================================

    with INPUT_FILE.open(
        "r",
        encoding="utf-8-sig",
        newline=""
    ) as f:

        reader = csv.DictReader(f)

        zap_rows = list(reader)
        zap_fields = reader.fieldnames or []

    print("=" * 70)
    print("ZAP → OWASP TOP 10:2025 MAPPING")
    print("=" * 70)

    print(
        f"\nZAP input rows: {len(zap_rows)}"
    )

    # -----------------------------------------------------
    # Locate CWE field in ZAP data
    # -----------------------------------------------------

    zap_cwe_column = find_column(
        zap_fields,
        [
            "cwe_id",
            "cwe",
            "cweid"
        ]
    )

    if zap_cwe_column is None:

        raise ValueError(
            "\nCWE column not found in ZAP dataset.\n"
            f"Available columns:\n{zap_fields}"
        )

    print(
        f"ZAP CWE column: {zap_cwe_column}"
    )

    # =====================================================
    # LOAD OWASP 2025 CWE MAP
    # =====================================================

    with OWASP_MAP_FILE.open(
        "r",
        encoding="utf-8-sig",
        newline=""
    ) as f:

        reader = csv.DictReader(f)

        owasp_rows = list(reader)
        owasp_fields = reader.fieldnames or []

    print(
        f"OWASP mapping rows: {len(owasp_rows)}"
    )

    # -----------------------------------------------------
    # Locate mapping columns
    # -----------------------------------------------------

    owasp_cwe_column = find_column(
        owasp_fields,
        [
            "cwe",
            "cwe_id",
            "cweid"
        ]
    )

    owasp_category_column = find_column(
        owasp_fields,
        [
            "owasp_category",
            "owasp_id",
            "category"
        ]
    )

    owasp_name_column = find_column(
        owasp_fields,
        [
            "owasp_name",
            "category_name",
            "name"
        ]
    )

    if owasp_cwe_column is None:
        raise ValueError(
            "\nCWE column not found in OWASP mapping.\n"
            f"Available columns:\n{owasp_fields}"
        )

    if owasp_category_column is None:
        raise ValueError(
            "\nOWASP category column not found.\n"
            f"Available columns:\n{owasp_fields}"
        )

    if owasp_name_column is None:
        raise ValueError(
            "\nOWASP category name column not found.\n"
            f"Available columns:\n{owasp_fields}"
        )

    print(
        f"OWASP CWE column     : {owasp_cwe_column}"
    )

    print(
        f"OWASP category column: {owasp_category_column}"
    )

    print(
        f"OWASP name column    : {owasp_name_column}"
    )

    # =====================================================
    # BUILD CWE → OWASP MAPPING
    # =====================================================

    cwe_to_owasp = {}

    for row in owasp_rows:

        cwe = normalize_cwe(
            row.get(
                owasp_cwe_column,
                ""
            )
        )

        if not cwe:
            continue

        category = str(
            row.get(
                owasp_category_column,
                ""
            )
        ).strip()

        name = str(
            row.get(
                owasp_name_column,
                ""
            )
        ).strip()

        if cwe not in cwe_to_owasp:
            cwe_to_owasp[cwe] = []

        mapping = (category, name)

        if mapping not in cwe_to_owasp[cwe]:

            cwe_to_owasp[cwe].append(
                mapping
            )

    print(
        f"\nUnique CWE keys in OWASP map: "
        f"{len(cwe_to_owasp)}"
    )

    # =====================================================
    # MAP EACH ZAP FINDING
    # =====================================================

    output_rows = []

    mapped_rows = 0
    unmapped_rows = 0
    no_cwe_rows = 0

    unique_findings = set()

    for zap_row in zap_rows:

        finding_id = zap_row.get(
            "finding_id",
            ""
        )

        unique_findings.add(finding_id)

        raw_cwe = zap_row.get(
            zap_cwe_column,
            ""
        )

        cwe = normalize_cwe(raw_cwe)

        # -------------------------------------------------
        # No CWE
        # -------------------------------------------------

        if not cwe:

            no_cwe_rows += 1

            output_rows.append({
                **zap_row,
                "normalized_cwe": "",
                "owasp_category": "",
                "owasp_name": "",
                "owasp_mapping_status": "NO_CWE"
            })

            continue

        # -------------------------------------------------
        # CWE has OWASP mappings
        # -------------------------------------------------

        mappings = cwe_to_owasp.get(
            cwe,
            []
        )

        if mappings:

            for category, name in mappings:

                output_rows.append({
                    **zap_row,
                    "normalized_cwe": cwe,
                    "owasp_category": category,
                    "owasp_name": name,
                    "owasp_mapping_status": "MAPPED"
                })

                mapped_rows += 1

        # -------------------------------------------------
        # CWE exists but has no OWASP 2025 mapping
        # -------------------------------------------------

        else:

            unmapped_rows += 1

            output_rows.append({
                **zap_row,
                "normalized_cwe": cwe,
                "owasp_category": "",
                "owasp_name": "",
                "owasp_mapping_status": "NO_OWASP_MAPPING"
            })

    # =====================================================
    # OUTPUT COLUMNS
    # =====================================================

    output_fields = list(zap_fields)

    output_fields.extend([
        "normalized_cwe",
        "owasp_category",
        "owasp_name",
        "owasp_mapping_status"
    ])

    # Remove accidental duplicate column names
    output_fields = list(
        dict.fromkeys(output_fields)
    )

    # =====================================================
    # WRITE OUTPUT
    # =====================================================

    with OUTPUT_FILE.open(
        "w",
        encoding="utf-8",
        newline=""
    ) as f:

        writer = csv.DictWriter(
            f,
            fieldnames=output_fields
        )

        writer.writeheader()
        writer.writerows(output_rows)

    # =====================================================
    # STATISTICS
    # =====================================================

    category_counts = {}

    for row in output_rows:

        category = row.get(
            "owasp_category",
            ""
        ).strip()

        if not category:
            continue

        category_counts[category] = (
            category_counts.get(category, 0) + 1
        )

    # =====================================================
    # DISPLAY RESULTS
    # =====================================================

    print("\n" + "-" * 70)
    print("MAPPING RESULTS")
    print("-" * 70)

    print(
        f"Unique ZAP findings : "
        f"{len(unique_findings)}"
    )

    print(
        f"Input rows          : "
        f"{len(zap_rows)}"
    )

    print(
        f"Output rows         : "
        f"{len(output_rows)}"
    )

    print(
        f"Mapped rows         : "
        f"{mapped_rows}"
    )

    print(
        f"No OWASP mapping    : "
        f"{unmapped_rows}"
    )

    print(
        f"No CWE              : "
        f"{no_cwe_rows}"
    )

    print("\nOWASP Top 10:2025 distribution:")
    print("-" * 70)

    if category_counts:

        for category, count in sorted(
            category_counts.items()
        ):

            print(
                f"{category}: {count}"
            )

    else:

        print("No mappings found.")

    print("\nOutput file:")
    print(
        OUTPUT_FILE.resolve()
    )

    print("\nDone.")


if __name__ == "__main__":
    main()