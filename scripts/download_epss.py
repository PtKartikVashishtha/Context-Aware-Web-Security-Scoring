from pathlib import Path
import requests


DATE = "2025-12-31"

URL = (
    f"https://epss.empiricalsecurity.com/"
    f"epss_scores-{DATE}.csv.gz"
)

OUTPUT_DIR = Path("data/raw/epss")
OUTPUT_FILE = OUTPUT_DIR / f"epss_scores-{DATE}.csv.gz"


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    print("Downloading full historical EPSS dataset...")
    print(f"Date: {DATE}")
    print(f"URL: {URL}")
    print()

    headers = {
        "User-Agent": "CAQ-WSRA-Research/1.0"
    }

    response = requests.get(
        URL,
        headers=headers,
        stream=True,
        timeout=120
    )

    response.raise_for_status()

    total_size = int(
        response.headers.get("content-length", 0)
    )

    downloaded = 0

    with OUTPUT_FILE.open("wb") as f:
        for chunk in response.iter_content(
            chunk_size=1024 * 1024
        ):
            if not chunk:
                continue

            f.write(chunk)
            downloaded += len(chunk)

            if total_size:
                percent = (
                    downloaded / total_size
                ) * 100

                print(
                    f"\rDownloaded: {percent:6.2f}%",
                    end=""
                )

    print()
    print()
    print("Download complete.")
    print(f"Saved to: {OUTPUT_FILE}")
    print(
        f"File size: "
        f"{OUTPUT_FILE.stat().st_size / (1024 * 1024):.2f} MB"
    )


if __name__ == "__main__":
    main()