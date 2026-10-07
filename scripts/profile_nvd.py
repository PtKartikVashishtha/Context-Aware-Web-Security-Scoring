import gzip
import json


FILE = "data/raw/nvd/nvdcve-2.0-2025.json.gz"


def main():
    print("Loading NVD 2025 feed...")

    with gzip.open(FILE, "rt", encoding="utf-8") as f:
        data = json.load(f)

    vulnerabilities = data["vulnerabilities"]

    print(f"\nTotal CVEs: {len(vulnerabilities):,}")

    # Counters
    cvss31_count = 0
    cvss40_count = 0

    primary_cvss31_count = 0
    primary_cvss40_count = 0

    no_cvss_count = 0
    weaknesses_count = 0

    cwe_count = 0

    for item in vulnerabilities:

        cve = item["cve"]

        metrics = cve.get("metrics", {})

        v31 = metrics.get("cvssMetricV31", [])
        v40 = metrics.get("cvssMetricV40", [])

        if v31:
            cvss31_count += 1

        if v40:
            cvss40_count += 1

        # Check for NVD primary CVSS 3.1
        for metric in v31:
            if metric.get("type") == "Primary":
                primary_cvss31_count += 1
                break

        # Check for primary CVSS 4.0
        for metric in v40:
            if metric.get("type") == "Primary":
                primary_cvss40_count += 1
                break

        if not v31 and not v40:
            no_cvss_count += 1

        weaknesses = cve.get("weaknesses", [])

        if weaknesses:
            weaknesses_count += 1

            for weakness in weaknesses:
                for desc in weakness.get("description", []):
                    value = desc.get("value", "")

                    if value.startswith("CWE-"):
                        cwe_count += 1

    print("\n========== CVSS COVERAGE ==========")

    print(f"CVSS 3.1 present        : {cvss31_count:,}")
    print(f"CVSS 4.0 present        : {cvss40_count:,}")

    print(f"Primary CVSS 3.1        : {primary_cvss31_count:,}")
    print(f"Primary CVSS 4.0        : {primary_cvss40_count:,}")

    print(f"No CVSS 3.1/4.0         : {no_cvss_count:,}")

    print("\n========== CWE COVERAGE ==========")

    print(f"CVEs with weaknesses    : {weaknesses_count:,}")
    print(f"CWE references found    : {cwe_count:,}")

    print("\n========== EXAMPLE ==========")

    first = vulnerabilities[0]["cve"]

    print("CVE:", first["id"])

    print("\nWeaknesses:")
    for weakness in first.get("weaknesses", []):
        for desc in weakness.get("description", []):
            print(
                f"  {desc.get('value')} "
                f"(source={weakness.get('source')}, "
                f"type={weakness.get('type')})"
            )

    print("\nCVSS 3.1:")
    for metric in first.get("metrics", {}).get("cvssMetricV31", []):
        cvss = metric["cvssData"]

        print(
            f"  source={metric.get('source')}, "
            f"type={metric.get('type')}, "
            f"score={cvss.get('baseScore')}, "
            f"AV={cvss.get('attackVector')}, "
            f"AC={cvss.get('attackComplexity')}, "
            f"PR={cvss.get('privilegesRequired')}, "
            f"UI={cvss.get('userInteraction')}"
        )


if __name__ == "__main__":
    main()