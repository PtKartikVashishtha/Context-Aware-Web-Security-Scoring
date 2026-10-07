import csv
from pathlib import Path


# =========================================================
# FILE PATHS
# =========================================================

INPUT_FILE = Path(
    "data/processed/zap_findings.csv"
)

OUTPUT_FILE = Path(
    "data/processed/zap_findings_unique.csv"
)


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
    # Read existing ZAP findings
    # -----------------------------------------------------

    with INPUT_FILE.open(
        "r",
        encoding="utf-8-sig",
        newline=""
    ) as f:

        reader = csv.DictReader(f)
        rows = list(reader)
        fieldnames = reader.fieldnames or []

    print("=" * 70)
    print("FIXING ZAP FINDING IDS")
    print("=" * 70)

    print(f"\nInput rows: {len(rows)}")

    # -----------------------------------------------------
    # Preserve the original ID
    # -----------------------------------------------------

    if "original_finding_id" not in fieldnames:

        fieldnames.append(
            "original_finding_id"
        )

    # Make finding_id the first column
    fieldnames = [
        "finding_id"
    ] + [
        field
        for field in fieldnames
        if field != "finding_id"
    ]

    # -----------------------------------------------------
    # Generate guaranteed unique IDs
    # -----------------------------------------------------

    used_ids = set()

    for index, row in enumerate(rows, start=1):

        original_id = row.get(
            "finding_id",
            ""
        )

        row["original_finding_id"] = original_id

        # Example:
        # ZAP-000001
        # ZAP-000002
        # ZAP-000003

        new_id = f"ZAP-{index:06d}"

        # Safety check
        if new_id in used_ids:
            raise RuntimeError(
                f"Duplicate generated ID: {new_id}"
            )

        used_ids.add(new_id)

        row["finding_id"] = new_id

    # -----------------------------------------------------
    # Final uniqueness check
    # -----------------------------------------------------

    final_ids = [
        row["finding_id"]
        for row in rows
    ]

    if len(final_ids) != len(set(final_ids)):
        raise RuntimeError(
            "Finding IDs are still not unique."
        )

    # -----------------------------------------------------
    # Write cleaned dataset
    # -----------------------------------------------------

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
        writer.writerows(rows)

    # -----------------------------------------------------
    # Summary
    # -----------------------------------------------------

    print("\n" + "-" * 70)
    print("RESULT")
    print("-" * 70)

    print(
        f"Input rows             : {len(rows)}"
    )

    print(
        f"Unique finding IDs     : {len(set(final_ids))}"
    )

    print(
        f"Duplicate IDs after fix: "
        f"{len(final_ids) - len(set(final_ids))}"
    )

    print(
        f"\nOutput file:\n"
        f"{OUTPUT_FILE.resolve()}"
    )

    print("\nExample IDs:")

    for row in rows[:5]:
        print(
            f"{row['finding_id']}  "
            f"(original: {row['original_finding_id']})"
        )

    print("\nDone.")


if __name__ == "__main__":
    main()