import json


FILE = "data/raw/kev/known_exploited_vulnerabilities.json"


with open(FILE, "r", encoding="utf-8") as f:
    data = json.load(f)

print("Top-level keys:")
print(data.keys())

print()
print("Catalog version:")
print(data.get("catalogVersion"))

print()
print("Catalog count:")
print(data.get("count"))

print()
print("Actual entries:")
print(len(data.get("vulnerabilities", [])))

print()
print("First entry:")

print(
    json.dumps(
        data["vulnerabilities"][0],
        indent=2
    )
)