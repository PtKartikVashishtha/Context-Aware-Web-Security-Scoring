import csv
import json
from collections import Counter
from pathlib import Path

from sklearn.model_selection import train_test_split


# =========================================================
# PATHS
# =========================================================

INPUT_FILE = Path(
    "data/processed/public_dataset_v1.csv"
)

OUTPUT_DIR = Path(
    "data/processed/ml"
)

CLEAN_FILE = OUTPUT_DIR / "ml_dataset_clean.csv"
TRAIN_FILE = OUTPUT_DIR / "ml_train.csv"
TEST_FILE = OUTPUT_DIR / "ml_test.csv"
MANIFEST_FILE = OUTPUT_DIR / "ml_dataset_manifest.json"
DUPLICATE_FILE = OUTPUT_DIR / "duplicate_cves.csv"


# =========================================================
# TARGET
# =========================================================

TARGET_COLUMN = "known_exploitation"


# =========================================================
# INITIAL ML FEATURES
#
# These are the features for our FIRST ML experiment.
#
# EPSS is deliberately NOT used as a training feature.
# It will be an external benchmark.
#
# vuln_status and exploit_available_evidence are also
# excluded from the first experiment because their temporal
# provenance is not clean enough for us to treat them as
# leakage-safe predictive features at this stage.
# =========================================================

NUMERIC_FEATURES = [
    "cvss_base_score",
]

CATEGORICAL_FEATURES = [
    "attack_vector",
    "attack_complexity",
    "privileges_required",
    "user_interaction",
    "primary_cwe",
    "primary_owasp_category",
]

MODEL_FEATURES = (
    NUMERIC_FEATURES +
    CATEGORICAL_FEATURES
)


# =========================================================
# BENCHMARK / IDENTIFIER COLUMNS
# These are retained for analysis but are NOT model inputs.
# =========================================================

REFERENCE_COLUMNS = [
    "cve_id",
    "published_date",
    "epss",
    "epss_percentile",
    "epss_available",
]


# =========================================================
# REQUIRED COLUMNS
# =========================================================

REQUIRED_COLUMNS = (
    ["cve_id", TARGET_COLUMN]
    + MODEL_FEATURES
    + REFERENCE_COLUMNS[1:]
)


# =========================================================
# HELPERS
# =========================================================

def clean_text(value):
    """Normalize text fields."""

    if value is None:
        return ""

    return str(value).strip()


def clean_numeric(value):
    """Convert numeric field to a clean representation."""

    value = clean_text(value)

    if value == "":
        return ""

    try:
        number = float(value)

        # Keep normal decimal representation
        return str(number)

    except ValueError:
        return ""


def normalize_categorical(value, unknown_label="UNKNOWN"):
    """Normalize categorical values."""

    value = clean_text(value)

    if value == "":
        return unknown_label

    return value


def load_csv(path):
    """Load CSV into a list of dictionaries."""

    with path.open(
        "r",
        encoding="utf-8-sig",
        newline=""
    ) as f:

        reader = csv.DictReader(f)

        rows = list(reader)
        fields = reader.fieldnames or []

    return rows, fields


def write_csv(path, rows, fields):
    """Write rows to CSV."""

    path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with path.open(
        "w",
        encoding="utf-8",
        newline=""
    ) as f:

        writer = csv.DictWriter(
            f,
            fieldnames=fields,
            extrasaction="ignore"
        )

        writer.writeheader()
        writer.writerows(rows)


# =========================================================
# MAIN
# =========================================================

def main():

    print("=" * 75)
    print("ML DATASET PREPARATION")
    print("=" * 75)

    # -----------------------------------------------------
    # Check source dataset
    # -----------------------------------------------------

    if not INPUT_FILE.exists():

        raise FileNotFoundError(
            f"\nMain dataset not found:\n"
            f"{INPUT_FILE.resolve()}"
        )

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    # -----------------------------------------------------
    # Load dataset
    # -----------------------------------------------------

    rows, columns = load_csv(INPUT_FILE)

    print(
        f"\nInput dataset : {INPUT_FILE}"
    )

    print(
        f"Input rows    : {len(rows)}"
    )

    print(
        f"Input columns : {len(columns)}"
    )

    # -----------------------------------------------------
    # Validate columns
    # -----------------------------------------------------

    missing_columns = [
        column
        for column in REQUIRED_COLUMNS
        if column not in columns
    ]

    if missing_columns:

        raise ValueError(
            "\nMissing required columns:\n"
            + "\n".join(
                f"  - {column}"
                for column in missing_columns
            )
        )

    print("\nRequired columns: OK")

    # -----------------------------------------------------
    # Duplicate CVE check
    # -----------------------------------------------------

    cve_counter = Counter(
        clean_text(row.get("cve_id", ""))
        for row in rows
    )

    duplicate_cves = {
        cve: count
        for cve, count in cve_counter.items()
        if cve and count > 1
    }

    if duplicate_cves:

        duplicate_rows = [
            row
            for row in rows
            if clean_text(row.get("cve_id", "")) in duplicate_cves
        ]

        write_csv(
            DUPLICATE_FILE,
            duplicate_rows,
            columns
        )

        raise ValueError(
            "\nDuplicate CVEs detected.\n"
            f"Found {len(duplicate_cves)} duplicate CVE IDs.\n"
            f"Details written to:\n"
            f"{DUPLICATE_FILE.resolve()}\n\n"
            "The script stopped so duplicates are not silently removed."
        )

    print(
        "Duplicate CVEs : 0"
    )

    # -----------------------------------------------------
    # Clean rows
    # -----------------------------------------------------

    clean_rows = []

    invalid_target_rows = []

    for row in rows:

        cleaned = {}

        # ---------------------------------------------
        # Identifier
        # ---------------------------------------------

        cleaned["cve_id"] = clean_text(
            row.get("cve_id", "")
        )

        # ---------------------------------------------
        # Numeric feature
        # ---------------------------------------------

        cleaned["cvss_base_score"] = clean_numeric(
            row.get("cvss_base_score", "")
        )

        # ---------------------------------------------
        # Categorical features
        # ---------------------------------------------

        for feature in CATEGORICAL_FEATURES:

            cleaned[feature] = normalize_categorical(
                row.get(feature, "")
            )

        # ---------------------------------------------
        # Target
        # ---------------------------------------------

        target = clean_text(
            row.get(TARGET_COLUMN, "")
        ).lower()

        if target in ("1", "true", "yes"):
            cleaned[TARGET_COLUMN] = "1"

        elif target in ("0", "false", "no"):
            cleaned[TARGET_COLUMN] = "0"

        else:

            invalid_target_rows.append(
                row.get("cve_id", "")
            )

            continue

        # ---------------------------------------------
        # Reference / benchmark columns
        # ---------------------------------------------

        cleaned["published_date"] = clean_text(
            row.get("published_date", "")
        )

        cleaned["epss"] = clean_numeric(
            row.get("epss", "")
        )

        cleaned["epss_percentile"] = clean_numeric(
            row.get("epss_percentile", "")
        )

        cleaned["epss_available"] = clean_text(
            row.get("epss_available", "")
        )

        clean_rows.append(cleaned)

    # -----------------------------------------------------
    # Target validation
    # -----------------------------------------------------

    if invalid_target_rows:

        print(
            f"\nWARNING: {len(invalid_target_rows)} rows "
            "had invalid/missing targets and were excluded."
        )

    target_counts = Counter(
        row[TARGET_COLUMN]
        for row in clean_rows
    )

    positives = target_counts.get("1", 0)
    negatives = target_counts.get("0", 0)

    print("\nTarget distribution:")
    print("-" * 75)
    print(f"Known exploited     : {positives}")
    print(f"Not known exploited : {negatives}")
    print(f"Total               : {len(clean_rows)}")

    if positives < 2:
        raise ValueError(
            "\nNot enough positive samples for stratified splitting."
        )

    # -----------------------------------------------------
    # Write clean dataset
    # -----------------------------------------------------

    clean_fields = [
        "cve_id",
        *MODEL_FEATURES,
        TARGET_COLUMN,
        *REFERENCE_COLUMNS[1:],
    ]

    write_csv(
        CLEAN_FILE,
        clean_rows,
        clean_fields
    )

    # -----------------------------------------------------
    # Stratified train/test split
    # -----------------------------------------------------

    train_rows, test_rows = train_test_split(
        clean_rows,
        test_size=0.20,
        random_state=42,
        stratify=[
            row[TARGET_COLUMN]
            for row in clean_rows
        ],
    )

    write_csv(
        TRAIN_FILE,
        train_rows,
        clean_fields
    )

    write_csv(
        TEST_FILE,
        test_rows,
        clean_fields
    )

    # -----------------------------------------------------
    # Train/test target distribution
    # -----------------------------------------------------

    train_counts = Counter(
        row[TARGET_COLUMN]
        for row in train_rows
    )

    test_counts = Counter(
        row[TARGET_COLUMN]
        for row in test_rows
    )

    # -----------------------------------------------------
    # Dataset manifest
    # -----------------------------------------------------

    manifest = {
        "source_dataset": str(INPUT_FILE),
        "total_samples": len(clean_rows),
        "train_samples": len(train_rows),
        "test_samples": len(test_rows),

        "target": {
            "column": TARGET_COLUMN,
            "positive_label": "1",
            "negative_label": "0",
            "positive_samples": positives,
            "negative_samples": negatives,
        },

        "model_features": {
            "numeric": NUMERIC_FEATURES,
            "categorical": CATEGORICAL_FEATURES,
            "all": MODEL_FEATURES,
        },

        "reference_columns": REFERENCE_COLUMNS,

        "excluded_from_first_model": [
            "epss",
            "epss_percentile",
            "vuln_status",
            "exploit_available_evidence",
            "all_cwes",
            "all_owasp_categories",
            "published_timestamp",
        ],

        "split": {
            "method": "train_test_split",
            "test_size": 0.20,
            "stratified": True,
            "random_state": 42,
        },

        "train_target_distribution": {
            "known_exploited": train_counts.get("1", 0),
            "not_known_exploited": train_counts.get("0", 0),
        },

        "test_target_distribution": {
            "known_exploited": test_counts.get("1", 0),
            "not_known_exploited": test_counts.get("0", 0),
        },

        "important_notes": [
            "EPSS is retained only as an external benchmark.",
            "Known exploitation is the prediction target and is never used as a feature.",
            "Categorical variables will be encoded inside the training pipeline.",
            "Missing CVSS values are retained for later model-side imputation.",
            "No random undersampling or synthetic positive samples are performed."
        ],
    }

    with MANIFEST_FILE.open(
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            manifest,
            f,
            indent=4
        )

    # -----------------------------------------------------
    # Final report
    # -----------------------------------------------------

    print("\n" + "=" * 75)
    print("PREPARATION COMPLETE")
    print("=" * 75)

    print("\nFiles created:")

    print(
        f"  Clean dataset : {CLEAN_FILE.resolve()}"
    )

    print(
        f"  Train dataset : {TRAIN_FILE.resolve()}"
    )

    print(
        f"  Test dataset  : {TEST_FILE.resolve()}"
    )

    print(
        f"  Manifest      : {MANIFEST_FILE.resolve()}"
    )

    print("\nModel features:")
    for feature in MODEL_FEATURES:
        print(f"  - {feature}")

    print("\nTrain distribution:")
    print(
        f"  Exploited     : {train_counts.get('1', 0)}"
    )
    print(
        f"  Not exploited : {train_counts.get('0', 0)}"
    )

    print("\nTest distribution:")
    print(
        f"  Exploited     : {test_counts.get('1', 0)}"
    )
    print(
        f"  Not exploited : {test_counts.get('0', 0)}"
    )

    print("\nEPSS remains available only for later benchmarking.")

    print("\nDone.")


if __name__ == "__main__":
    main()