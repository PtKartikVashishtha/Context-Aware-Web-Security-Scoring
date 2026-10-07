from pathlib import Path
import csv
import re
import requests


BASE_URL = "https://raw.githubusercontent.com/OWASP/Top10/master/2025/docs/en"

CATEGORIES = {
    "A01": (
        "Broken Access Control",
        "A01_2025-Broken_Access_Control.md",
    ),
    "A02": (
        "Security Misconfiguration",
        "A02_2025-Security_Misconfiguration.md",
    ),
    "A03": (
        "Software Supply Chain Failures",
        "A03_2025-Software_Supply_Chain_Failures.md",
    ),
    "A04": (
        "Cryptographic Failures",
        "A04_2025-Cryptographic_Failures.md",
    ),
    "A05": (
        "Injection",
        "A05_2025-Injection.md",
    ),
    "A06": (
        "Insecure Design",
        "A06_2025-Insecure_Design.md",
    ),
    "A07": (
        "Authentication Failures",
        "A07_2025-Authentication_Failures.md",
    ),
    "A08": (
        "Software or Data Integrity Failures",
        "A08_2025-Software_or_Data_Integrity_Failures.md",
    ),
    "A09": (
        "Security Logging and Alerting Failures",
        "A09_2025-Security_Logging_and_Alerting_Failures.md",
    ),
    "A10": (
        "Mishandling of Exceptional Conditions",
        "A10_2025-Mishandling_of_Exceptional_Conditions.md",
    ),
}

OUTPUT = Path("data/processed/owasp_2025_cwe_map.csv")


def extract_mapped_cwes(markdown: str):
    """
    Extract CWE IDs only from the official
    'List of Mapped CWEs' section.
    """

    match = re.search(
        r"## List of Mapped CWEs(.*?)(?=\n## |\Z)",
        markdown,
        flags=re.DOTALL
    )

    if not match:
        raise ValueError("Could not find 'List of Mapped CWEs' section.")

    section = match.group(1)

    cwes = re.findall(r"\bCWE-(\d+)\b", section)

    return sorted(set(cwes), key=int)


def main():
    rows = []

    for code, (name, filename) in CATEGORIES.items():
        url = f"{BASE_URL}/{filename}"

        print(f"Downloading {code}...")

        response = requests.get(url, timeout=30)
        response.raise_for_status()

        cwes = extract_mapped_cwes(response.text)

        print(f"  Official mapped CWEs: {len(cwes)}")

        for number in cwes:
            rows.append([
                f"CWE-{number}",
                f"{code}:2025",
                name,
            ])

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    with OUTPUT.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)

        writer.writerow([
            "cwe",
            "owasp_category",
            "owasp_name",
        ])

        writer.writerows(rows)

    unique_cwes = len(set(row[0] for row in rows))

    print()
    print("========================================")
    print("OWASP Top 10:2025 mapping created")
    print("========================================")
    print(f"Total mappings : {len(rows)}")
    print(f"Unique CWEs    : {unique_cwes}")
    print(f"Output         : {OUTPUT}")


if __name__ == "__main__":
    main()