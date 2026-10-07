import csv
import gzip


FILE = "data/raw/epss/epss_scores-2025-12-31.csv.gz"


def main():

    total = 0
    first_rows = []

    with gzip.open(
        FILE,
        "rt",
        encoding="utf-8",
        errors="replace"
    ) as f:

        reader = csv.reader(f)

        for row in reader:

            # Keep first 10 rows for inspection
            if len(first_rows) < 10:
                first_rows.append(row)

            total += 1

    print("======================================")
    print("EPSS DATASET PROFILE")
    print("======================================")

    print(f"Total lines including header : {total:,}")

    print()
    print("First 10 rows")
    print("--------------------------------------")

    for row in first_rows:
        print(row)


if __name__ == "__main__":
    main()