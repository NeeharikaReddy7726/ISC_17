"""
Script to collect and prepare a real, balanced dataset of legitimate and phishing URLs.

DATASET SOURCES & METHODOLOGY:
1. Phishing URLs: PhishTank Verified Online Feed
   Source: https://data.phishtank.com/data/online-valid.csv (HTTPS)
   Operated by: Cisco Talos.
   Authentication: Optional API Key via PHISHTANK_API_KEY environment variable.
   Description: Active, community-submitted phishing URLs verified by human and automated review.

2. Legitimate URLs: Tranco Research Top Sites List
   Source: https://tranco-list.eu/top-1m.csv.zip (Official Tranco Endpoint)
   Description: Academic consensus ranking combining Alexa, Cisco Umbrella, and Majestic.
   IMPORTANT METHODOLOGY & LIMITATION NOTE:
   Tranco ranks popular domain names. To evaluate full URLs, domains are combined with
   diverse structural paths. These serve as statistical proxies for legitimate web structures,
   not individually audited safe links.

SAFETY GUARANTEE:
This script only downloads and parses CSV/text data.
It DOES NOT visit, open, crawl, or resolve any collected target URLs.
"""

import csv
import io
import json
import os
import random
import zipfile
from datetime import datetime, timezone
import requests

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET_PATH = os.path.join(CURRENT_DIR, "dataset.csv")
METADATA_PATH = os.path.join(CURRENT_DIR, "dataset_metadata.json")

# Official endpoints
PHISHTANK_BASE_URL = "https://data.phishtank.com/data"
TRANCO_OFFICIAL_ZIP_URL = "https://tranco-list.eu/top-1m.csv.zip"

# Diverse path patterns with varying depths and realistic structures to prevent artificial length splits
PATH_DISTRIBUTION_TEMPLATES = [
    # Category 1: Root / Landing pages (very common in QR codes, e.g. menus, business cards)
    "",
    "/",
    "/",
    # Category 2: Short informational pages
    "/about",
    "/contact",
    "/faq",
    "/help",
    "/privacy",
    "/terms",
    "/services",
    "/pricing",
    # Category 3: Standard content & documentation paths
    "/docs/overview",
    "/blog/recent-updates",
    "/news/announcements",
    "/wiki/Information_technology",
    "/wiki/Computer_science",
    "/portal/dashboard",
    # Category 4: Multi-segment paths with query parameters & search queries
    "/search?q=technology",
    "/search?q=university+admissions",
    "/items/view?id=10482&category=hardware",
    "/articles/2026/03/guide?ref=homepage&source=web",
    "/catalog/browse?filter=all&sort=date",
    "/user/profile?view=summary&tab=activity",
]


def get_phishtank_url() -> str:
    """
    Constructs the PhishTank download URL.
    Uses PHISHTANK_API_KEY from environment if configured, otherwise uses the public feed.
    """
    api_key = os.getenv("PHISHTANK_API_KEY", "").strip()
    if api_key:
        print("  [Auth] Using PhishTank API Key from environment variable 'PHISHTANK_API_KEY'.")
        return f"{PHISHTANK_BASE_URL}/{api_key}/online-valid.csv"
    else:
        print("  [Notice] No 'PHISHTANK_API_KEY' found. Using public rate-limited endpoint.")
        return f"{PHISHTANK_BASE_URL}/online-valid.csv"


def fetch_phishtank_urls(count: int = 3000) -> list[str]:
    """
    Downloads verified phishing URLs from PhishTank HTTPS feed.
    Enforces deduplication, verified status check, and checks response status codes.
    """
    print(f"[1/2] Fetching verified phishing URLs from PhishTank (HTTPS)...")
    url = get_phishtank_url()
    headers = {"User-Agent": "phishtank/QR-Shield-College-Project"}

    try:
        response = requests.get(url, headers=headers, timeout=35)
        if response.status_code in (403, 429, 509):
            raise PermissionError(
                f"PhishTank public rate limit exceeded (HTTP {response.status_code}).\n"
                "To resolve this, obtain a free API key at https://phishtank.org/developer_info.php\n"
                "and set it in your environment: $env:PHISHTANK_API_KEY = 'your_key_here'"
            )
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"Failed to download PhishTank dataset: {str(e)}")

    reader = csv.DictReader(io.StringIO(response.text))
    unique_phishing = []
    seen = set()

    for row in reader:
        raw_url = row.get("url", "").strip()
        verified = row.get("verified", "").strip().lower()

        # Accept only active, verified phishing URLs
        if verified == "yes" and raw_url.startswith(("http://", "https://")):
            if raw_url not in seen:
                seen.add(raw_url)
                unique_phishing.append(raw_url)
                if len(unique_phishing) >= count:
                    break

    # Strict check: verify target count was actually achieved
    if len(unique_phishing) < count:
        raise RuntimeError(
            f"Insufficient phishing URLs collected from PhishTank: "
            f"requested {count}, but only found {len(unique_phishing)} unique verified URLs."
        )

    print(f"  --> Successfully collected {len(unique_phishing)} unique verified phishing URLs.")
    return unique_phishing


def fetch_tranco_legitimate_urls(count: int = 3000) -> list[str]:
    """
    Downloads official daily Tranco top 1M sites ZIP archive, extracts in-memory,
    and constructs structurally varied legitimate URL samples.
    """
    print(f"[2/2] Fetching official Tranco Top Sites list (ZIP)...")
    try:
        response = requests.get(TRANCO_OFFICIAL_ZIP_URL, timeout=35)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"Failed to download official Tranco list: {str(e)}")

    # Extract top-1m.csv directly in-memory from the ZIP stream
    with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
        csv_filename = archive.namelist()[0]
        with archive.open(csv_filename) as csv_file:
            text_stream = io.TextIOWrapper(csv_file, encoding="utf-8")
            reader = csv.reader(text_stream)

            unique_legit = []
            seen = set()

            for row in reader:
                if len(row) >= 2:
                    domain = row[1].strip()
                    if not domain:
                        continue

                    # Realistic distribution: mix of protocols, www prefix, and varied path structures
                    protocol = "https" if random.random() > 0.08 else "http"
                    formatted_domain = f"www.{domain}" if random.random() > 0.5 else domain
                    path = random.choice(PATH_DISTRIBUTION_TEMPLATES)
                    constructed_url = f"{protocol}://{formatted_domain}{path}"

                    if constructed_url not in seen:
                        seen.add(constructed_url)
                        unique_legit.append(constructed_url)
                        if len(unique_legit) >= count:
                            break

    # Strict check: verify target count was actually achieved
    if len(unique_legit) < count:
        raise RuntimeError(
            f"Insufficient legitimate URLs generated from Tranco: "
            f"requested {count}, but only collected {len(unique_legit)} unique URLs."
        )

    print(f"  --> Successfully collected {len(unique_legit)} unique legitimate URL proxies.")
    return unique_legit


def build_and_save_dataset(target_count_per_class: int = 3000):
    """
    Builds a balanced 50/50 dataset, saves to CSV, and generates an audit metadata record.
    """
    random.seed(42)

    phishing_urls = fetch_phishtank_urls(count=target_count_per_class)
    legit_urls = fetch_tranco_legitimate_urls(count=target_count_per_class)

    # Cross-contamination prevention: ensure no legitimate URL duplicates a phishing entry
    phish_set = set(phishing_urls)
    legit_urls = [u for u in legit_urls if u not in phish_set]

    # Verify balance
    if len(phishing_urls) != len(legit_urls) or len(phishing_urls) != target_count_per_class:
        raise ValueError(
            f"Dataset imbalance detected: Phishing={len(phishing_urls)}, "
            f"Legitimate={len(legit_urls)}. Expected exactly {target_count_per_class} each."
        )

    # Combine into labeled rows (0 = Legitimate, 1 = Phishing)
    rows = []
    for u in legit_urls:
        rows.append({"url": u, "label": 0})
    for u in phishing_urls:
        rows.append({"url": u, "label": 1})

    # Shuffle rows deterministically
    random.shuffle(rows)

    # 1. Save dataset.csv
    with open(DATASET_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["url", "label"])
        writer.writeheader()
        writer.writerows(rows)

    # 2. Save metadata audit documentation
    download_timestamp = datetime.now(timezone.utc).isoformat()
    api_key_configured = bool(os.getenv("PHISHTANK_API_KEY", "").strip())

    metadata = {
        "dataset_name": "QR Shield Phishing and Legitimate URL Dataset",
        "download_timestamp_utc": download_timestamp,
        "total_samples": len(rows),
        "class_balance": {
            "legitimate_samples": len(legit_urls),
            "phishing_samples": len(phishing_urls),
            "ratio": "50/50"
        },
        "sources": {
            "phishing": {
                "provider": "PhishTank (Cisco Talos)",
                "url": PHISHTANK_BASE_URL,
                "api_key_used": api_key_configured,
                "criterion": "verified == 'yes'"
            },
            "legitimate": {
                "provider": "Tranco Top 1M Research List (Official)",
                "url": TRANCO_OFFICIAL_ZIP_URL,
                "disclaimer": (
                    "Tranco domains represent high-traffic, popular domains utilized "
                    "as academic proxies for legitimate website structures; they are "
                    "not individually human-verified safe URLs."
                )
            }
        }
    }

    with open(METADATA_PATH, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    print(f"\n[SUCCESS] Balanced dataset saved to: {DATASET_PATH}")
    print(f"[SUCCESS] Dataset audit metadata saved to: {METADATA_PATH}")
    print(f"Total samples: {len(rows)} (Legitimate: {len(legit_urls)}, Phishing: {len(phishing_urls)})")


if __name__ == "__main__":
    build_and_save_dataset(target_count_per_class=3000)
