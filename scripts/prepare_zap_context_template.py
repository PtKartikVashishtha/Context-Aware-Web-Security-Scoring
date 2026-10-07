import csv
from pathlib import Path


# =========================================================
# FILE PATHS
# =========================================================

INPUT_FILE = Path(
    "data/processed/zap_findings_unique_owasp_2025.csv"
)

OUTPUT_FILE = Path(
    "data/processed/zap_context_annotation_template.csv"
)


# =========================================================
# CONTEXT PARAMETERS
# =========================================================

CONTEXT_COLUMNS = [
    "exposure_level",
    "asset_criticality",
    "data_sensitivity",
    "authentication_requirement",
    "exploit_availability",
    "known_exploitation_status",
]


# =========================================================
# MAIN
# =========================================================

def main():

    if not INPUT_FILE.exists():
        raise FileNotFoundError(
            f"Input file not found:\n{INPUT_FILE.resolve()}"
        )

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    # -----------------------------------------------------
    # Read mapped ZAP dataset
    # -----------------------------------------------------

    with INPUT_FILE.open(
        "r",
        encoding="utf-8-sig",
        newline=""
    ) as f:

        reader = csv.DictReader(f)

        rows = list(reader)
        original_fields = reader.fieldnames or []

    print("=" * 70)
    print("PREPARING ZAP CONTEXT ANNOTATION DATASET")
    print("=" * 70)

    print(
        f"\nInput rows: {len(rows)}"
    )

    # -----------------------------------------------------
    # Add contextual columns
    # -----------------------------------------------------

    output_fields = list(original_fields)

    for column in CONTEXT_COLUMNS:

        if column not in output_fields:
            output_fields.append(column)

    # -----------------------------------------------------
    # Add annotation status
    # -----------------------------------------------------

    annotation_columns = [
        "context_annotation_status",
        "context_annotation_notes",
    ]

    for column in annotation_columns:

        if column not in output_fields:
            output_fields.append(column)

    # -----------------------------------------------------
    # Initialize context fields as blank
    #
    # We deliberately DO NOT assign values here.
    # -----------------------------------------------------

    for row in rows:

        for column in CONTEXT_COLUMNS:

            row[column] = ""

        row["context_annotation_status"] = (
            "PENDING"
        )

        row["context_annotation_notes"] = ""

    # -----------------------------------------------------
    # Write template
    # -----------------------------------------------------

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
        writer.writerows(rows)

    # -----------------------------------------------------
    # Display result
    # -----------------------------------------------------

    print("\n" + "-" * 70)

    print(
        f"Output file:\n"
        f"{OUTPUT_FILE.resolve()}"
    )

    print(
        f"\nRows preserved: {len(rows)}"
    )

    print("\nContext columns added:")

    for column in CONTEXT_COLUMNS:
        print(f"  - {column}")

    print("\nAnnotation columns added:")

    for column in annotation_columns:
        print(f"  - {column}")

    print(
        "\nNo context values were automatically assigned."
    )

    print("\nDone.")


if __name__ == "__main__":
    main()