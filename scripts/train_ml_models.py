import csv
import json
from pathlib import Path

import joblib
import numpy as np

from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder


# =========================================================
# PATHS
# =========================================================

TRAIN_FILE = Path(
    "data/processed/ml/ml_train.csv"
)

TEST_FILE = Path(
    "data/processed/ml/ml_test.csv"
)

MODEL_DIR = Path(
    "models"
)

RESULT_DIR = Path(
    "data/processed/ml/results"
)

RESULT_FILE = RESULT_DIR / "model_results.csv"


# =========================================================
# TARGET
# =========================================================

TARGET = "known_exploitation"


# =========================================================
# FEATURES
#
# Column order matters because we will use numerical
# column positions in ColumnTransformer.
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

FEATURES = (
    NUMERIC_FEATURES +
    CATEGORICAL_FEATURES
)


# Numeric column index:
#   0 = cvss_base_score
#
# Categorical column indices:
#   1 = attack_vector
#   2 = attack_complexity
#   3 = privileges_required
#   4 = user_interaction
#   5 = primary_cwe
#   6 = primary_owasp_category

NUMERIC_INDICES = [0]

CATEGORICAL_INDICES = [1, 2, 3, 4, 5, 6]


# =========================================================
# HELPERS
# =========================================================

def load_csv(path):
    """Load CSV file into a list of dictionaries."""

    with path.open(
        "r",
        encoding="utf-8-sig",
        newline=""
    ) as f:

        return list(csv.DictReader(f))


def build_feature_matrix(rows):
    """
    Convert CSV rows into a proper 2-D NumPy object array.

    Shape:

        (number_of_samples, number_of_features)

    Feature order:

        0 CVSS
        1 Attack Vector
        2 Attack Complexity
        3 Privileges Required
        4 User Interaction
        5 Primary CWE
        6 Primary OWASP Category
    """

    X = []
    y = []

    for row in rows:

        # -------------------------------------------------
        # Numeric feature
        # -------------------------------------------------

        cvss_value = row.get(
            "cvss_base_score",
            ""
        ).strip()

        if cvss_value == "":
            cvss = np.nan

        else:
            try:
                cvss = float(cvss_value)

            except ValueError:
                cvss = np.nan

        # -------------------------------------------------
        # Categorical features
        # -------------------------------------------------

        categorical_values = []

        for feature in CATEGORICAL_FEATURES:

            value = row.get(
                feature,
                ""
            ).strip()

            if value == "":
                value = "UNKNOWN"

            categorical_values.append(value)

        # -------------------------------------------------
        # Build one sample
        # -------------------------------------------------

        sample = [
            cvss,
            *categorical_values
        ]

        X.append(sample)

        # -------------------------------------------------
        # Target
        # -------------------------------------------------

        target = row.get(
            TARGET,
            ""
        ).strip()

        if target not in ("0", "1"):

            raise ValueError(
                f"Invalid target value '{target}' "
                f"for CVE {row.get('cve_id', 'UNKNOWN')}"
            )

        y.append(int(target))

    return (
        np.array(X, dtype=object),
        np.array(y, dtype=int)
    )


def evaluate_model(
    model_name,
    model,
    X_test,
    y_test,
):
    """Evaluate a trained binary classifier."""

    probabilities = model.predict_proba(
        X_test
    )[:, 1]

    # Default classification threshold.
    predictions = (
        probabilities >= 0.50
    ).astype(int)

    roc_auc = roc_auc_score(
        y_test,
        probabilities
    )

    pr_auc = average_precision_score(
        y_test,
        probabilities
    )

    precision = precision_score(
        y_test,
        predictions,
        zero_division=0
    )

    recall = recall_score(
        y_test,
        predictions,
        zero_division=0
    )

    f1 = f1_score(
        y_test,
        predictions,
        zero_division=0
    )

    tn, fp, fn, tp = confusion_matrix(
        y_test,
        predictions,
        labels=[0, 1]
    ).ravel()

    result = {
        "model": model_name,
        "roc_auc": roc_auc,
        "pr_auc": pr_auc,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "true_negative": int(tn),
        "false_positive": int(fp),
        "false_negative": int(fn),
        "true_positive": int(tp),
    }

    return result, probabilities


# =========================================================
# MAIN
# =========================================================

def main():

    print("=" * 75)
    print("FIRST ML EXPERIMENT")
    print("=" * 75)

    # -----------------------------------------------------
    # Check files
    # -----------------------------------------------------

    if not TRAIN_FILE.exists():

        raise FileNotFoundError(
            f"\nTraining file not found:\n"
            f"{TRAIN_FILE.resolve()}"
        )

    if not TEST_FILE.exists():

        raise FileNotFoundError(
            f"\nTest file not found:\n"
            f"{TEST_FILE.resolve()}"
        )

    MODEL_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    RESULT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    # -----------------------------------------------------
    # Load data
    # -----------------------------------------------------

    train_rows = load_csv(
        TRAIN_FILE
    )

    test_rows = load_csv(
        TEST_FILE
    )

    X_train, y_train = build_feature_matrix(
        train_rows
    )

    X_test, y_test = build_feature_matrix(
        test_rows
    )

    print(
        f"\nTraining samples: {len(y_train)}"
    )

    print(
        f"Test samples    : {len(y_test)}"
    )

    print(
        f"Training positives: {int(y_train.sum())}"
    )

    print(
        f"Test positives    : {int(y_test.sum())}"
    )

    print(
        f"Feature matrix shape: {X_train.shape}"
    )

    print("\nFeatures:")

    for index, feature in enumerate(FEATURES):

        print(
            f"  {index}: {feature}"
        )

    # -----------------------------------------------------
    # Preprocessing
    # -----------------------------------------------------

    numeric_pipeline = Pipeline(
        steps=[
            (
                "imputer",
                SimpleImputer(
                    strategy="median"
                )
            )
        ]
    )

    categorical_pipeline = Pipeline(
        steps=[
            (
                "imputer",
                SimpleImputer(
                    strategy="most_frequent"
                )
            ),
            (
                "onehot",
                OneHotEncoder(
                    handle_unknown="ignore"
                )
            )
        ]
    )

    preprocessor = ColumnTransformer(
        transformers=[
            (
                "numeric",
                numeric_pipeline,
                NUMERIC_INDICES
            ),
            (
                "categorical",
                categorical_pipeline,
                CATEGORICAL_INDICES
            ),
        ]
    )

    # -----------------------------------------------------
    # Models
    # -----------------------------------------------------

    models = {

        "logistic_regression":
            LogisticRegression(
                class_weight="balanced",
                max_iter=3000,
                random_state=42
            ),

        "random_forest":
            RandomForestClassifier(
                n_estimators=400,
                class_weight="balanced_subsample",
                min_samples_leaf=2,
                random_state=42,
                n_jobs=-1
            ),
    }

    results = []

    trained_models = {}

    # -----------------------------------------------------
    # Train each model
    # -----------------------------------------------------

    for model_name, classifier in models.items():

        print("\n" + "-" * 75)

        print(
            f"TRAINING: {model_name}"
        )

        print("-" * 75)

        pipeline = Pipeline(
            steps=[
                (
                    "preprocessor",
                    preprocessor
                ),
                (
                    "classifier",
                    classifier
                ),
            ]
        )

        # ---------------------------------------------
        # Train
        # ---------------------------------------------

        pipeline.fit(
            X_train,
            y_train
        )

        print("Training complete.")

        # ---------------------------------------------
        # Evaluate
        # ---------------------------------------------

        result, probabilities = evaluate_model(
            model_name,
            pipeline,
            X_test,
            y_test
        )

        results.append(result)

        trained_models[model_name] = (
            pipeline,
            probabilities
        )

        print(
            f"\nROC-AUC : {result['roc_auc']:.4f}"
        )

        print(
            f"PR-AUC  : {result['pr_auc']:.4f}"
        )

        print(
            f"Precision: {result['precision']:.4f}"
        )

        print(
            f"Recall   : {result['recall']:.4f}"
        )

        print(
            f"F1       : {result['f1']:.4f}"
        )

        print("\nConfusion matrix:")

        print(
            f"TN = {result['true_negative']}"
        )

        print(
            f"FP = {result['false_positive']}"
        )

        print(
            f"FN = {result['false_negative']}"
        )

        print(
            f"TP = {result['true_positive']}"
        )

        # ---------------------------------------------
        # Save model
        # ---------------------------------------------

        model_path = (
            MODEL_DIR /
            f"{model_name}.joblib"
        )

        joblib.dump(
            pipeline,
            model_path
        )

        print(
            f"\nSaved model: "
            f"{model_path.resolve()}"
        )

    # -----------------------------------------------------
    # Select best model
    # -----------------------------------------------------

    best_result = max(
        results,
        key=lambda result: result["pr_auc"]
    )

    best_model_name = best_result[
        "model"
    ]

    best_model = trained_models[
        best_model_name
    ][0]

    best_model_path = (
        MODEL_DIR /
        "best_ml_model.joblib"
    )

    joblib.dump(
        best_model,
        best_model_path
    )

    # -----------------------------------------------------
    # Save results
    # -----------------------------------------------------

    result_fields = [
        "model",
        "roc_auc",
        "pr_auc",
        "precision",
        "recall",
        "f1",
        "true_negative",
        "false_positive",
        "false_negative",
        "true_positive",
    ]

    with RESULT_FILE.open(
        "w",
        encoding="utf-8",
        newline=""
    ) as f:

        writer = csv.DictWriter(
            f,
            fieldnames=result_fields
        )

        writer.writeheader()
        writer.writerows(results)

    # -----------------------------------------------------
    # Save experiment metadata
    # -----------------------------------------------------

    metadata = {

        "training_file": str(
            TRAIN_FILE
        ),

        "test_file": str(
            TEST_FILE
        ),

        "target": TARGET,

        "features": FEATURES,

        "models": list(
            models.keys()
        ),

        "best_model": best_model_name,

        "model_selection_metric": "PR-AUC",

        "classification_threshold": 0.50,

        "random_state": 42,

        "test_size": 0.20,

        "class_weighting": True,

        "epss_used_as_feature": False,

        "target_definition": (
            "Historical CISA KEV membership "
            "by the dataset cutoff"
        ),

        "note": (
            "The KEV-derived target is an operational "
            "exploitation label, not proof that an "
            "unlisted vulnerability is never exploitable."
        ),
    }

    metadata_file = (
        RESULT_DIR /
        "experiment_metadata.json"
    )

    with metadata_file.open(
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            metadata,
            f,
            indent=4
        )

    # -----------------------------------------------------
    # Final summary
    # -----------------------------------------------------

    print("\n" + "=" * 75)
    print("ML EXPERIMENT COMPLETE")
    print("=" * 75)

    print(
        f"\nBest model by PR-AUC: "
        f"{best_model_name}"
    )

    print(
        f"Best PR-AUC: "
        f"{best_result['pr_auc']:.4f}"
    )

    print(
        f"\nBest model:"
        f"\n{best_model_path.resolve()}"
    )

    print(
        f"\nResults:"
        f"\n{RESULT_FILE.resolve()}"
    )

    print(
        f"\nMetadata:"
        f"\n{metadata_file.resolve()}"
    )

    print("\nDone.")


if __name__ == "__main__":
    main()