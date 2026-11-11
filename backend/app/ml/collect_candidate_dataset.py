"""
Phase 1: Candidate Dataset Collection Pipeline for QR Shield.

Collects real, structurally diverse legitimate and malicious/phishing URLs from
publicly documented index APIs, sitemaps, and threat feeds into separate candidate
files (`dataset_candidate.csv` and `dataset_candidate_metadata.json`).

SAFETY & PRESERVATION GUARANTEES:
1. Never overwrites existing `dataset.csv`, `dataset_metadata.json`, `feature_extractor.py`,
   or `phishing_rf_model.joblib`.
2. Strictly NEVER opens, crawls, or sends HTTP requests to collected target URLs.
   Only fetches documented metadata/feed endpoints listed in PLANNED_NETWORK_DESTINATIONS.
3. Explicitly logs and records inaccessible or rate-limited feeds instead of silently
   substituting synthetic URLs.
"""

import csv
import io
import json
import os
import random
import re
import time
import xml.etree.ElementTree as ET
import zipfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests
import tldextract

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
CANDIDATE_DATASET_PATH = os.path.join(CURRENT_DIR, "dataset_candidate.csv")
CANDIDATE_METADATA_PATH = os.path.join(CURRENT_DIR, "dataset_candidate_metadata.json")
PRODUCTION_DATASET_PATH = os.path.join(CURRENT_DIR, "dataset.csv")

# Offline Public Suffix List extractor (zero network lookups)
_TLD_EXTRACTOR = tldextract.TLDExtract(cache_dir=None, suffix_list_urls=None)

REQUEST_HEADERS = {
    "User-Agent": "QR-Shield-College-Security-Research/1.0 (dataset-audit)"
}

# ---------------------------------------------------------------------------
# Explicit Network Destinations (for user review prior to execution)
# ---------------------------------------------------------------------------
PHISHTANK_BASE_URL = "https://data.phishtank.com/data"
OPENPHISH_FEED_URL = "https://openphish.com/feed.txt"
URLHAUS_RECENT_CSV_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"
TRANCO_OFFICIAL_ZIP_URL = "https://tranco-list.eu/top-1m.csv.zip"
COMMONCRAWL_COLLINFO_URL = "https://index.commoncrawl.org/collinfo.json"
WIKIPEDIA_RANDOM_API_URL = (
    "https://en.wikipedia.org/w/api.php"
    "?action=query&list=random&rnnamespace=0&rnlimit=100&format=json"
)

# Carefully curated institutional, government, educational, standards & developer
# documentation sitemap endpoints (static XML index files only).
CURATED_SITEMAP_SOURCES: List[Dict[str, str]] = [
    {
        "name": "python_docs_sitemap",
        "url": "https://docs.python.org/3/sitemap.xml",
        "criterion": "Official Python Software Foundation documentation sitemap",
    },
    {
        "name": "scikit_learn_sitemap",
        "url": "https://scikit-learn.org/stable/sitemap.xml",
        "criterion": "Official Scikit-learn library documentation sitemap",
    },
    {
        "name": "fastapi_docs_sitemap",
        "url": "https://fastapi.tiangolo.com/sitemap.xml",
        "criterion": "Official FastAPI framework documentation sitemap",
    },
    {
        "name": "owasp_sitemap",
        "url": "https://owasp.org/sitemap.xml",
        "criterion": "Official OWASP Foundation cybersecurity standards sitemap",
    },
    {
        "name": "nist_sitemap",
        "url": "https://www.nist.gov/sitemap.xml",
        "criterion": "Official U.S. National Institute of Standards and Technology (.gov) sitemap",
    },
]

# Carefully curated authoritative domains queried via Common Crawl CDX metadata
# (never queried directly; metadata fetched only from index.commoncrawl.org).
CURATED_INSTITUTIONAL_DOMAINS: List[str] = [
    "nist.gov",
    "cisa.gov",
    "nasa.gov",
    "loc.gov",
    "noaa.gov",
    "mit.edu",
    "stanford.edu",
    "berkeley.edu",
    "harvard.edu",
    "ox.ac.uk",
    "cam.ac.uk",
    "ethz.ch",
    "python.org",
    "mozilla.org",
    "w3.org",
    "ietf.org",
    "owasp.org",
    "scikit-learn.org",
    "tiangolo.com",
    "pytorch.org",
    "numpy.org",
    "pandas.pydata.org",
    "sqlite.org",
    "opencv.org",
    "kernel.org",
    "apache.org",
    "rust-lang.org",
    "go.dev",
    "react.dev",
    "wikipedia.org",
    "github.com",
    "arxiv.org",
    "khanacademy.org",
]

# Regex helpers for categorizing realistic URL structures
_VERSION_OR_EXT_RE = re.compile(
    r"(?:/v?\d+(?:\.\d+)*|\.(?:html?|php|aspx?|jsp|xml|json|pdf|md))(?:$|[/?#])",
    re.IGNORECASE,
)
_DOCS_HINT_RE = re.compile(
    r"(?:^docs\.|^developer\.|/docs/|/doc/|/manual/|/reference/|/guide/|/tutorial/|/wiki/|/standards/|/library/)",
    re.IGNORECASE,
)


def extract_root_domain(url: str) -> str:
    """Extracts registrable root domain (eTLD+1) using offline tldextract."""
    try:
        ext = _TLD_EXTRACTOR(str(url).strip())
        root = ext.top_domain_under_public_suffix or ext.domain
        return root.lower() if root else "unknown"
    except Exception:
        return "unknown"


def classify_url_structure(url: str) -> Dict[str, Any]:
    """
    Inspects structural attributes of a URL (without modifying feature_extractor.py)
    to verify coverage across root pages, deep nested paths, docs, subdomains,
    query parameters, and versioned/extension URLs.
    """
    parsed = urlparse(url.strip())
    host = parsed.netloc.lower().split(":")[0]
    path = parsed.path or ""
    segments = [s for s in path.split("/") if s]
    root = extract_root_domain(url)

    is_root_page = len(segments) == 0 and not parsed.query
    is_deep_nested = len(segments) >= 3
    has_query = bool(parsed.query)
    has_non_www_subdomain = bool(host and host != root and not host.startswith("www."))
    is_docs = bool(_DOCS_HINT_RE.search(host + path))
    is_versioned_or_ext = bool(_VERSION_OR_EXT_RE.search(path))

    tags = []
    if is_root_page:
        tags.append("root_page")
    if is_deep_nested:
        tags.append("deep_nested_path")
    if is_docs:
        tags.append("documentation_page")
    if has_non_www_subdomain:
        tags.append("non_www_subdomain")
    if has_query:
        tags.append("query_params")
    if is_versioned_or_ext:
        tags.append("versioned_or_extension")
    if not tags:
        tags.append("standard_shallow_path")

    return {
        "primary_tag": tags[0],
        "tags": tags,
        "segment_count": len(segments),
        "root_domain": root,
    }


def _now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize_candidate_url(raw_url: str) -> Optional[str]:
    u = str(raw_url or "").strip()
    if not u.lower().startswith(("http://", "https://")):
        return None
    if len(u) > 2048 or any(ch.isspace() for ch in u):
        return None
    parsed = urlparse(u)
    if not parsed.netloc:
        return None
    return u


class CandidatePool:
    """Tracks deduplicated URLs with strict per-root-domain caps."""

    def __init__(self, max_per_root_domain: int):
        self.max_per_root_domain = max_per_root_domain
        self.seen_urls: set[str] = set()
        self.root_counts: Counter = Counter()
        self.records: List[Dict[str, Any]] = []
        self.duplicates_removed: int = 0
        self.capped_by_root: int = 0

    def try_add(
        self,
        raw_url: str,
        label: int,
        source: str,
        source_criterion: str,
        excluded_roots: Optional[set[str]] = None,
    ) -> str:
        url = _normalize_candidate_url(raw_url)
        if not url:
            return "invalid"

        if url in self.seen_urls:
            self.duplicates_removed += 1
            return "duplicate"

        struct = classify_url_structure(url)
        root = struct["root_domain"]
        if root == "unknown":
            return "invalid"

        if excluded_roots and root in excluded_roots:
            return "excluded_root"

        if self.root_counts[root] >= self.max_per_root_domain:
            self.capped_by_root += 1
            return "capped"

        self.seen_urls.add(url)
        self.root_counts[root] += 1
        self.records.append(
            {
                "url": url,
                "label": label,
                "source": source,
                "source_criterion": source_criterion,
                "root_domain": root,
                "url_structure": "|".join(struct["tags"]),
                "collected_at_utc": _now_utc_iso(),
            }
        )
        return "added"


# ---------------------------------------------------------------------------
# Phishing Feed Collectors
# ---------------------------------------------------------------------------

def collect_phishtank(pool: CandidatePool, max_items: int) -> Dict[str, Any]:
    api_key = os.getenv("PHISHTANK_API_KEY", "").strip()
    endpoint = (
        f"{PHISHTANK_BASE_URL}/{api_key}/online-valid.csv"
        if api_key
        else f"{PHISHTANK_BASE_URL}/online-valid.csv"
    )
    redacted_endpoint = (
        f"{PHISHTANK_BASE_URL}/<PHISHTANK_API_KEY>/online-valid.csv"
        if api_key
        else endpoint
    )
    report: Dict[str, Any] = {
        "source": "phishtank",
        "endpoint": redacted_endpoint,
        "status": "pending",
        "http_status": None,
        "raw_records_seen": 0,
        "accepted_records": 0,
        "note": "",
    }

    try:
        resp = requests.get(
            endpoint,
            headers={"User-Agent": "phishtank/QR-Shield-Dataset-Audit"},
            timeout=35,
        )
        report["http_status"] = resp.status_code
        if resp.status_code in (403, 429, 509):
            report["status"] = "rate_limited"
            report["note"] = (
                f"PhishTank returned HTTP {resp.status_code} rate-limit without an approved API key."
            )
            return report
        resp.raise_for_status()
    except requests.RequestException as exc:
        report["status"] = "inaccessible"
        report["note"] = str(exc)
        return report

    reader = csv.DictReader(io.StringIO(resp.text))
    for row in reader:
        if report["accepted_records"] >= max_items:
            break
        raw_url = row.get("url", "").strip()
        verified = row.get("verified", "").strip().lower()
        if verified != "yes":
            continue
        report["raw_records_seen"] += 1
        outcome = pool.try_add(
            raw_url=raw_url,
            label=1,
            source="phishtank",
            source_criterion="PhishTank verified == 'yes' in online-valid.csv",
        )
        if outcome == "added":
            report["accepted_records"] += 1

    report["status"] = "success" if report["accepted_records"] > 0 else "empty"
    return report


def collect_openphish(pool: CandidatePool, max_items: int) -> Dict[str, Any]:
    report: Dict[str, Any] = {
        "source": "openphish",
        "endpoint": OPENPHISH_FEED_URL,
        "status": "pending",
        "http_status": None,
        "raw_records_seen": 0,
        "accepted_records": 0,
        "note": "",
    }

    try:
        resp = requests.get(OPENPHISH_FEED_URL, headers=REQUEST_HEADERS, timeout=25)
        report["http_status"] = resp.status_code
        if resp.status_code in (403, 429):
            report["status"] = "rate_limited"
            report["note"] = f"OpenPhish returned HTTP {resp.status_code}."
            return report
        resp.raise_for_status()
    except requests.RequestException as exc:
        report["status"] = "inaccessible"
        report["note"] = str(exc)
        return report

    for line in resp.text.splitlines():
        if report["accepted_records"] >= max_items:
            break
        candidate = line.strip()
        if not candidate:
            continue
        report["raw_records_seen"] += 1
        outcome = pool.try_add(
            raw_url=candidate,
            label=1,
            source="openphish",
            source_criterion="OpenPhish active verified phishing community feed",
        )
        if outcome == "added":
            report["accepted_records"] += 1

    report["status"] = "success" if report["accepted_records"] > 0 else "empty"
    return report


def collect_urlhaus(pool: CandidatePool, max_items: int) -> Dict[str, Any]:
    report: Dict[str, Any] = {
        "source": "urlhaus",
        "endpoint": URLHAUS_RECENT_CSV_URL,
        "status": "pending",
        "http_status": None,
        "raw_records_seen": 0,
        "accepted_records": 0,
        "note": "URLhaus tracks malicious/malware-distribution URLs (recorded transparently in source_criterion).",
    }

    try:
        resp = requests.get(URLHAUS_RECENT_CSV_URL, headers=REQUEST_HEADERS, timeout=35)
        report["http_status"] = resp.status_code
        if resp.status_code in (403, 429):
            report["status"] = "rate_limited"
            report["note"] = f"URLhaus returned HTTP {resp.status_code}."
            return report
        resp.raise_for_status()
    except requests.RequestException as exc:
        report["status"] = "inaccessible"
        report["note"] = str(exc)
        return report

    content_bytes = resp.content
    text_data: Optional[str] = None
    if zipfile.is_zipfile(io.BytesIO(content_bytes)):
        with zipfile.ZipFile(io.BytesIO(content_bytes)) as zf:
            csv_name = zf.namelist()[0]
            text_data = zf.read(csv_name).decode("utf-8", errors="replace")
    else:
        text_data = resp.text

    data_lines = [ln for ln in text_data.splitlines() if ln.strip()]
    header_cols: Optional[List[str]] = None
    filtered_rows: List[str] = []
    for ln in data_lines:
        stripped = ln.lstrip()
        if stripped.startswith("#"):
            # URLhaus includes a commented header line: "# id,dateadded,url,url_status,..."
            candidate_hdr = stripped.lstrip("#").strip()
            if "url" in candidate_hdr.lower() and "," in candidate_hdr:
                header_cols = [c.strip().strip('"').lower() for c in candidate_hdr.split(",")]
            continue
        filtered_rows.append(ln)

    url_idx = header_cols.index("url") if header_cols and "url" in header_cols else 2
    threat_idx = header_cols.index("threat") if header_cols and "threat" in header_cols else None

    reader = csv.reader(filtered_rows)
    for row in reader:
        if report["accepted_records"] >= max_items:
            break
        if len(row) <= url_idx:
            continue
        raw_url = row[url_idx].strip()
        if not raw_url or raw_url.lower() == "url":
            continue
        report["raw_records_seen"] += 1
        if threat_idx is not None and len(row) > threat_idx:
            threat_val = row[threat_idx].strip() or "malicious_url"
        else:
            threat_val = "malicious_url"
        outcome = pool.try_add(
            raw_url=raw_url,
            label=1,
            source="urlhaus",
            source_criterion=f"abuse.ch URLhaus recent malicious URL feed (threat={threat_val})",
        )
        if outcome == "added":
            report["accepted_records"] += 1

    report["status"] = "success" if report["accepted_records"] > 0 else "empty"
    return report


# ---------------------------------------------------------------------------
# Legitimate Source Collectors (Zero arbitrary crawling of unknown sites)
# ---------------------------------------------------------------------------

def _get_latest_commoncrawl_cdx_api() -> Tuple[Optional[str], Optional[int], str]:
    try:
        resp = requests.get(COMMONCRAWL_COLLINFO_URL, headers=REQUEST_HEADERS, timeout=25)
        if resp.status_code != 200:
            return None, resp.status_code, f"collinfo.json returned HTTP {resp.status_code}"
        collections = resp.json()
        if not collections or "cdx-api" not in collections[0]:
            return None, resp.status_code, "collinfo.json contained no valid cdx-api entries"
        return collections[0]["cdx-api"], resp.status_code, collections[0].get("id", "latest")
    except Exception as exc:
        return None, None, str(exc)


def collect_commoncrawl_for_domains(
    pool: CandidatePool,
    domains: List[str],
    source_name: str,
    source_criterion: str,
    cdx_api_url: Optional[str],
    max_items: int,
    excluded_roots: set[str],
    per_domain_cdx_limit: int = 25,
) -> Dict[str, Any]:
    report: Dict[str, Any] = {
        "source": source_name,
        "endpoint": cdx_api_url or COMMONCRAWL_COLLINFO_URL,
        "status": "pending",
        "domains_queried": 0,
        "domains_with_results": 0,
        "raw_records_seen": 0,
        "accepted_records": 0,
        "rate_limited_queries": 0,
        "note": "",
    }

    if not cdx_api_url:
        report["status"] = "inaccessible"
        report["note"] = "Common Crawl CDX endpoint unavailable from collinfo.json."
        return report

    for dom in domains:
        if report["accepted_records"] >= max_items:
            break
        report["domains_queried"] += 1

        params = {
            "url": dom,
            "matchType": "domain",
            "output": "json",
            "fl": "url,status,mime",
            "filter": ["status:200", "mime:text/html"],
            "limit": str(per_domain_cdx_limit),
        }

        try:
            resp = requests.get(cdx_api_url, params=params, headers=REQUEST_HEADERS, timeout=20)
            if resp.status_code in (429, 503):
                report["rate_limited_queries"] += 1
                time.sleep(0.8)
                continue
            if resp.status_code == 404:
                continue
            resp.raise_for_status()
        except requests.RequestException:
            continue

        domain_candidates: List[str] = []
        for line in resp.text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            captured_url = entry.get("url", "").strip()
            if captured_url:
                domain_candidates.append(captured_url)

        if domain_candidates:
            report["domains_with_results"] += 1

        # Prioritize structural diversity (root, deep nested, docs, non-www subdomain,
        # query params, versioned/extension) within this domain's CDX batch
        random.shuffle(domain_candidates)
        by_structure: Dict[str, List[str]] = defaultdict(list)
        for cand in domain_candidates:
            tag = classify_url_structure(cand)["primary_tag"]
            by_structure[tag].append(cand)

        ordered_candidates: List[str] = []
        while by_structure:
            for tag_key in list(by_structure.keys()):
                bucket = by_structure[tag_key]
                if bucket:
                    ordered_candidates.append(bucket.pop())
                if not bucket:
                    del by_structure[tag_key]

        for captured_url in ordered_candidates:
            if report["accepted_records"] >= max_items:
                break
            report["raw_records_seen"] += 1
            outcome = pool.try_add(
                raw_url=captured_url,
                label=0,
                source=source_name,
                source_criterion=source_criterion,
                excluded_roots=excluded_roots,
            )
            if outcome == "added":
                report["accepted_records"] += 1

        time.sleep(0.15)  # Polite pacing against Common Crawl index API

    if report["accepted_records"] > 0:
        report["status"] = "success"
    elif report["rate_limited_queries"] > 0:
        report["status"] = "rate_limited"
    else:
        report["status"] = "empty"
    return report


def fetch_tranco_sample_domains(sample_size: int = 350, rank_ceiling: int = 15000) -> Tuple[List[str], Dict[str, Any]]:
    report: Dict[str, Any] = {
        "source": "tranco_domain_sampling",
        "endpoint": TRANCO_OFFICIAL_ZIP_URL,
        "status": "pending",
        "http_status": None,
        "sampled_domains": 0,
        "note": "Used solely as a domain list to query real captured URLs from Common Crawl CDX index.",
    }
    try:
        resp = requests.get(TRANCO_OFFICIAL_ZIP_URL, headers=REQUEST_HEADERS, timeout=35)
        report["http_status"] = resp.status_code
        resp.raise_for_status()
    except requests.RequestException as exc:
        report["status"] = "inaccessible"
        report["note"] = str(exc)
        return [], report

    pool_domains: List[str] = []
    with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
        csv_name = zf.namelist()[0]
        with zf.open(csv_name) as f:
            reader = csv.reader(io.TextIOWrapper(f, encoding="utf-8"))
            for row in reader:
                if len(row) < 2:
                    continue
                try:
                    rank = int(row[0])
                except ValueError:
                    continue
                if rank > rank_ceiling:
                    break
                dom = row[1].strip().lower()
                if dom:
                    pool_domains.append(dom)

    if len(pool_domains) > sample_size:
        sampled = random.sample(pool_domains, sample_size)
    else:
        sampled = pool_domains

    report["status"] = "success" if sampled else "empty"
    report["sampled_domains"] = len(sampled)
    return sampled, report


def collect_curated_sitemaps(
    pool: CandidatePool,
    max_per_sitemap: int,
    excluded_roots: set[str],
) -> List[Dict[str, Any]]:
    reports: List[Dict[str, Any]] = []

    for item in CURATED_SITEMAP_SOURCES:
        rep: Dict[str, Any] = {
            "source": item["name"],
            "endpoint": item["url"],
            "status": "pending",
            "http_status": None,
            "raw_records_seen": 0,
            "accepted_records": 0,
            "note": "",
        }
        try:
            resp = requests.get(item["url"], headers=REQUEST_HEADERS, timeout=25)
            rep["http_status"] = resp.status_code
            if resp.status_code in (403, 429):
                rep["status"] = "rate_limited"
                rep["note"] = f"HTTP {resp.status_code} returned by sitemap endpoint."
                reports.append(rep)
                continue
            resp.raise_for_status()

            root_xml = ET.fromstring(resp.content)
            # Collect <loc> entries cleanly regardless of XML namespace
            locs = [
                elem.text.strip()
                for elem in root_xml.iter()
                if elem.tag.endswith("loc") and elem.text
            ]
            # Filter out nested sub-sitemap XML references when picking page URLs
            page_urls = [u for u in locs if not u.lower().endswith(".xml")]
            random.shuffle(page_urls)

            for u in page_urls:
                if rep["accepted_records"] >= max_per_sitemap:
                    break
                rep["raw_records_seen"] += 1
                outcome = pool.try_add(
                    raw_url=u,
                    label=0,
                    source=item["name"],
                    source_criterion=item["criterion"],
                    excluded_roots=excluded_roots,
                )
                if outcome == "added":
                    rep["accepted_records"] += 1

            rep["status"] = "success" if rep["accepted_records"] > 0 else "empty"
        except Exception as exc:
            rep["status"] = "inaccessible"
            rep["note"] = str(exc)

        reports.append(rep)

    return reports


def collect_wikipedia_api(
    pool: CandidatePool,
    max_items: int,
    excluded_roots: set[str],
) -> Dict[str, Any]:
    report: Dict[str, Any] = {
        "source": "wikipedia_api",
        "endpoint": WIKIPEDIA_RANDOM_API_URL,
        "status": "pending",
        "http_status": None,
        "raw_records_seen": 0,
        "accepted_records": 0,
        "note": "",
    }
    try:
        resp = requests.get(WIKIPEDIA_RANDOM_API_URL, headers=REQUEST_HEADERS, timeout=25)
        report["http_status"] = resp.status_code
        resp.raise_for_status()
        payload = resp.json()
        pages = payload.get("query", {}).get("random", [])
        for page in pages:
            if report["accepted_records"] >= max_items:
                break
            title = page.get("title", "").strip()
            if not title:
                continue
            slug = title.replace(" ", "_")
            article_url = f"https://en.wikipedia.org/wiki/{slug}"
            report["raw_records_seen"] += 1
            outcome = pool.try_add(
                raw_url=article_url,
                label=0,
                source="wikipedia_api",
                source_criterion="Official Wikimedia Action API random main-namespace encyclopedic articles",
                excluded_roots=excluded_roots,
            )
            if outcome == "added":
                report["accepted_records"] += 1
        report["status"] = "success" if report["accepted_records"] > 0 else "empty"
    except Exception as exc:
        report["status"] = "inaccessible"
        report["note"] = str(exc)

    return report


# ---------------------------------------------------------------------------
# Main Candidate Pipeline
# ---------------------------------------------------------------------------

def summarize_structures(records: List[Dict[str, Any]]) -> Dict[str, int]:
    counts: Counter = Counter()
    for rec in records:
        for tag in str(rec.get("url_structure", "")).split("|"):
            if tag:
                counts[tag] += 1
    return dict(counts)


def run_candidate_collection(
    target_per_class: int = 1500,
    max_per_root_domain: int = 5,
    random_seed: int = 42,
):
    """
    Collects candidate phishing and legitimate datasets cleanly into separate files:
    `dataset_candidate.csv` and `dataset_candidate_metadata.json`.
    """
    if os.path.abspath(CANDIDATE_DATASET_PATH) == os.path.abspath(PRODUCTION_DATASET_PATH):
        raise RuntimeError("Safety guard triggered: refusing to overwrite production dataset.csv.")

    random.seed(random_seed)
    start_time_utc = _now_utc_iso()

    print("=" * 76)
    print("QR SHIELD PHASE 1: CANDIDATE DATASET COLLECTION PIPELINE")
    print("=" * 76)
    print(f"Target per class: {target_per_class} | Max samples per eTLD+1 root domain: {max_per_root_domain}")

    source_reports: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------
    # Step 1: Collect Phishing / Malicious URLs
    # ------------------------------------------------------------------
    print("\n[Step 1] Collecting threat-feed URLs (PhishTank, OpenPhish, URLhaus)...")
    phish_pool = CandidatePool(max_per_root_domain=max_per_root_domain)

    pt_rep = collect_phishtank(phish_pool, max_items=target_per_class)
    source_reports.append(pt_rep)
    print(f"  - PhishTank: status={pt_rep['status']} (http={pt_rep['http_status']}), accepted={pt_rep['accepted_records']}")

    op_rep = collect_openphish(phish_pool, max_items=target_per_class)
    source_reports.append(op_rep)
    print(f"  - OpenPhish: status={op_rep['status']} (http={op_rep['http_status']}), accepted={op_rep['accepted_records']}")

    uh_remaining = max(0, target_per_class - len(phish_pool.records))
    uh_rep = collect_urlhaus(phish_pool, max_items=max(uh_remaining, 250))
    source_reports.append(uh_rep)
    print(f"  - URLhaus:   status={uh_rep['status']} (http={uh_rep['http_status']}), accepted={uh_rep['accepted_records']}")

    phish_roots = set(phish_pool.root_counts.keys())

    # ------------------------------------------------------------------
    # Step 2: Collect Diverse Real Legitimate URLs
    # ------------------------------------------------------------------
    print("\n[Step 2] Collecting diverse real legitimate URLs (Common Crawl + Curated Sitemaps + Tranco)...")
    legit_pool = CandidatePool(max_per_root_domain=max_per_root_domain)

    # 2a. Curated Sitemaps
    sitemap_reps = collect_curated_sitemaps(
        legit_pool,
        max_per_sitemap=max_per_root_domain,
        excluded_roots=phish_roots,
    )
    source_reports.extend(sitemap_reps)
    for rep in sitemap_reps:
        print(f"  - Sitemap ({rep['source']}): status={rep['status']}, accepted={rep['accepted_records']}")

    # 2b. Official Wikimedia API
    wiki_rep = collect_wikipedia_api(
        legit_pool,
        max_items=max_per_root_domain,
        excluded_roots=phish_roots,
    )
    source_reports.append(wiki_rep)
    print(f"  - Wikipedia API: status={wiki_rep['status']}, accepted={wiki_rep['accepted_records']}")

    # 2c. Common Crawl CDX Index API for curated institutional domains
    cdx_api_url, collinfo_status, collinfo_note = _get_latest_commoncrawl_cdx_api()
    print(f"  - Common Crawl Index Discovery: url={cdx_api_url} (status={collinfo_status}, info={collinfo_note})")

    cc_inst_rep = collect_commoncrawl_for_domains(
        pool=legit_pool,
        domains=CURATED_INSTITUTIONAL_DOMAINS,
        source_name="commoncrawl_institutional",
        source_criterion=(
            "Observed HTTP 200 text/html capture in Common Crawl CDX index under curated "
            "institutional/government/edu/documentation domain"
        ),
        cdx_api_url=cdx_api_url,
        max_items=min(400, target_per_class),
        excluded_roots=phish_roots,
        per_domain_cdx_limit=30,
    )
    source_reports.append(cc_inst_rep)
    print(f"  - Common Crawl (Institutional): status={cc_inst_rep['status']}, accepted={cc_inst_rep['accepted_records']}")

    # 2d. Common Crawl CDX Index API for sampled Tranco domains (proxies)
    tranco_domains, tranco_rep = fetch_tranco_sample_domains(sample_size=450, rank_ceiling=15000)
    source_reports.append(tranco_rep)
    print(f"  - Tranco Domain Sampling: status={tranco_rep['status']}, sampled={len(tranco_domains)}")

    remaining_legit = max(0, target_per_class - len(legit_pool.records))
    cc_tranco_rep = collect_commoncrawl_for_domains(
        pool=legit_pool,
        domains=tranco_domains,
        source_name="commoncrawl_tranco_proxy",
        source_criterion=(
            "Observed HTTP 200 text/html capture in Common Crawl CDX index under Tranco Top-15k "
            "popular domain (consensus popularity proxy, not individually safety-audited)"
        ),
        cdx_api_url=cdx_api_url,
        max_items=remaining_legit if remaining_legit > 0 else target_per_class,
        excluded_roots=phish_roots,
        per_domain_cdx_limit=20,
    )
    source_reports.append(cc_tranco_rep)
    print(f"  - Common Crawl (Tranco Proxies): status={cc_tranco_rep['status']}, accepted={cc_tranco_rep['accepted_records']}")

    # ------------------------------------------------------------------
    # Step 3: Balance Without Fabricating Data & Persist Candidate Files
    # ------------------------------------------------------------------
    phish_records = list(phish_pool.records)
    legit_records = list(legit_pool.records)

    if not phish_records or not legit_records:
        raise RuntimeError(
            f"Candidate collection failed to gather both classes: "
            f"Legitimate={len(legit_records)}, Phishing={len(phish_records)}."
        )

    balanced_n = min(target_per_class, len(phish_records), len(legit_records))
    random.shuffle(phish_records)

    # Preserve curated institutional/sitemap/Wikipedia URLs ahead of Tranco proxy downsampling
    curated_legit = [r for r in legit_records if r["source"] != "commoncrawl_tranco_proxy"]
    proxy_legit = [r for r in legit_records if r["source"] == "commoncrawl_tranco_proxy"]
    random.shuffle(curated_legit)
    random.shuffle(proxy_legit)
    prioritized_legit = curated_legit + proxy_legit

    final_phish = phish_records[:balanced_n]
    final_legit = prioritized_legit[:balanced_n]
    combined = final_legit + final_phish
    random.shuffle(combined)

    fieldnames = [
        "url",
        "label",
        "source",
        "source_criterion",
        "root_domain",
        "url_structure",
        "collected_at_utc",
    ]
    with open(CANDIDATE_DATASET_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(combined)

    final_legit_roots = {r["root_domain"] for r in final_legit}
    final_phish_roots = {r["root_domain"] for r in final_phish}

    metadata = {
        "dataset_name": "QR Shield Phase 1 Candidate Dataset",
        "collection_started_utc": start_time_utc,
        "collection_finished_utc": _now_utc_iso(),
        "config": {
            "target_per_class": target_per_class,
            "max_per_root_domain": max_per_root_domain,
            "random_seed": random_seed,
        },
        "class_counts": {
            "raw_collected_legitimate": len(legit_pool.records),
            "raw_collected_phishing": len(phish_pool.records),
            "final_balanced_legitimate": len(final_legit),
            "final_balanced_phishing": len(final_phish),
            "final_total": len(combined),
        },
        "deduplication_and_caps": {
            "legitimate_duplicates_removed": legit_pool.duplicates_removed,
            "phishing_duplicates_removed": phish_pool.duplicates_removed,
            "legitimate_capped_by_root_domain": legit_pool.capped_by_root,
            "phishing_capped_by_root_domain": phish_pool.capped_by_root,
        },
        "root_domain_counts": {
            "unique_root_domains_legitimate": len(final_legit_roots),
            "unique_root_domains_phishing": len(final_phish_roots),
            "cross_class_root_overlap": len(final_legit_roots.intersection(final_phish_roots)),
            "total_unique_root_domains": len(final_legit_roots.union(final_phish_roots)),
        },
        "structure_distribution": {
            "legitimate": summarize_structures(final_legit),
            "phishing": summarize_structures(final_phish),
        },
        "source_reports": source_reports,
        "collection_limitations": [
            "HTTP 200 status in Common Crawl is only a capture-health filter; benign labels rely on curated institutional domain provenance or Tranco consensus popularity proxies.",
            "Tranco-derived Common Crawl URLs serve as popular-domain proxies and are not individually human-audited safe pages.",
            "URLhaus entries reflect verified malware-distribution URLs rather than strictly credential-harvesting phishing pages; source and criterion are explicitly recorded per row.",
            "PhishTank unauthenticated requests may return HTTP 429 rate-limiting if PHISHTANK_API_KEY is not configured.",
            "No collected target URLs were visited, rendered, or verified live at collection time.",
        ],
    }

    with open(CANDIDATE_METADATA_PATH, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    print("\n" + "=" * 76)
    print(f"[DONE] Candidate dataset saved to:  {CANDIDATE_DATASET_PATH}")
    print(f"[DONE] Candidate metadata saved to: {CANDIDATE_METADATA_PATH}")
    print(f"Final balanced rows: {len(combined)} (Legitimate={len(final_legit)}, Phishing={len(final_phish)})")
    print("=" * 76)


if __name__ == "__main__":
    run_candidate_collection()
