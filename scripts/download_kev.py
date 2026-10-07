from pathlib import Path
import requests


URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)

OUTPUT = Path(
    "data/raw/kev/known_exploited_vulnerabilities.json"
)


def main():
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    print("Downloading CISA KEV catalog...")
    print(f"URL: {URL}")

    headers = {
        "User-Agent": "CAQ-WSRA-Research/1.0"
    }

    response = requests.get(
        URL,
        headers=headers,
        timeout=60
    )

    response.raise_for_status()

    OUTPUT.write_bytes(response.content)

    print()
    print("Download complete.")
    print(f"Saved to: {OUTPUT}")
    print(
        f"Size: {OUTPUT.stat().st_size / 1024:.2f} KB"
    )


if __name__ == "__main__":
    main()