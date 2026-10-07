from pathlib import Path
import requests
import sys


YEAR = 2025

BASE_URL = "https://nvd.nist.gov/feeds/json/cve/2.0"

OUTPUT_DIR = Path("data/raw/nvd")
OUTPUT_FILE = OUTPUT_DIR / f"nvdcve-2.0-{YEAR}.json.gz"


def main():
    url = f"{BASE_URL}/nvdcve-2.0-{YEAR}.json.gz"

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    print(f"Downloading NVD {YEAR} feed...")
    print(f"URL: {url}")
    print()

    try:
        response = requests.get(
            url,
            stream=True,
            timeout=60
        )
        response.raise_for_status()

    except requests.RequestException as e:
        print(f"Download failed: {e}")
        sys.exit(1)

    total_size = int(response.headers.get("content-length", 0))
    downloaded = 0

    with OUTPUT_FILE.open("wb") as f:
        for chunk in response.iter_content(chunk_size=1024 * 1024):
            if chunk:
                f.write(chunk)
                downloaded += len(chunk)

                if total_size:
                    percent = downloaded / total_size * 100
                    print(
                        f"\rDownloaded: {percent:6.2f}%",
                        end=""
                    )

    print()
    print()
    print("Download complete.")
    print(f"Saved to: {OUTPUT_FILE}")
    print(f"Size: {OUTPUT_FILE.stat().st_size / (1024 * 1024):.2f} MB")


if __name__ == "__main__":
    main()