import gzip
import json

FILE = "data/raw/nvd/nvdcve-2.0-2025.json.gz"


with gzip.open(FILE, "rt", encoding="utf-8") as f:
    data = json.load(f)


print("Top-level keys:")
print(data.keys())

print()
print("Schema:")
print(data.get("dataVersion"))

print()
print("Number of vulnerabilities:")
print(len(data["vulnerabilities"]))

print()
print("First CVE:")
print(
    json.dumps(
        data["vulnerabilities"][0],
        indent=2
    )[:10000]
)