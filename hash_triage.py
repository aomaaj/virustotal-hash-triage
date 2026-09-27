#!/usr/bin/env python3
"""
VirusTotal Hash Triage Tool
A lightweight threat intelligence automation tool for Tier 1 SOC analysts
and incident responders to quickly query and triage file hashes against the
VirusTotal API v3.
"""

import argparse
import json
import os
import re
import sys
from typing import Any, Dict, List, Optional
import urllib.error
import urllib.request

# Optional support for python-dotenv if installed
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

VT_API_BASE_URL = "https://www.virustotal.com/api/v3/files/"
HASH_REGEX = {
    "MD5": re.compile(r"^[a-fA-F0-9]{32}$"),
    "SHA-1": re.compile(r"^[a-fA-F0-9]{40}$"),
    "SHA-256": re.compile(r"^[a-fA-F0-9]{64}$"),
}


def validate_hash_format(hash_value: str) -> Optional[str]:
    """
    Validates if the provided string matches MD5, SHA-1, or SHA-256 specifications.
    Returns the hash type if valid, otherwise None.
    """
    for hash_type, pattern in HASH_REGEX.items():
        if pattern.match(hash_value):
            return hash_type
    return None


def get_api_key(cli_key: Optional[str] = None) -> str:
    """
    Retrieves the VirusTotal API key from CLI argument, environment variable,
    or user input prompt.
    """
    if cli_key:
        return cli_key.strip()

    env_key = os.getenv("VT_API_KEY")
    if env_key:
        return env_key.strip()

    # Check local .env file manually if python-dotenv is not installed
    if os.path.isfile(".env"):
        with open(".env", "r", encoding="utf-8") as env_file:
            for line in env_file:
                clean = line.strip()
                if clean.startswith("VT_API_KEY="):
                    val = clean.split("=", 1)[1].strip().strip('"').strip("'")
                    if val and val != "your_virustotal_api_key_here":
                        return val

    prompt_key = input("Enter your VirusTotal API Key: ").strip()
    if not prompt_key:
        print("[ERROR] VirusTotal API key is required to perform queries.")
        sys.exit(1)
    return prompt_key


def query_virustotal(hash_value: str, api_key: str) -> Dict[str, Any]:
    """
    Queries the VirusTotal API v3 for a given file hash using native standard library.
    Returns parsed result dictionary with standard status flags.
    """
    url = f"{VT_API_BASE_URL}{hash_value}"
    headers = {
        "x-apikey": api_key,
        "Accept": "application/json",
        "User-Agent": "SecurityTriageTool/1.0",
    }

    req = urllib.request.Request(url, headers=headers, method="GET")

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            status_code = resp.status
            response_body = resp.read().decode("utf-8")
            data_json = json.loads(response_body)
    except urllib.error.HTTPError as http_err:
        status_code = http_err.code
        data_json = {}
    except urllib.error.URLError as url_err:
        return {
            "hash": hash_value,
            "status": "error",
            "message": f"Network error occurred: {url_err.reason}",
        }
    except Exception as exc:
        return {
            "hash": hash_value,
            "status": "error",
            "message": f"Unexpected error occurred: {exc}",
        }

    if status_code == 200:
        data = data_json.get("data", {})
        attributes = data.get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        threat_class = attributes.get("popular_threat_classification", {})

        popular_category = threat_class.get("suggested_threat_label", "N/A")
        file_names = attributes.get("names", [])
        primary_name = file_names[0] if file_names else "Unknown"
        file_type = attributes.get("type_description", "Unknown")
        reputation = attributes.get("reputation", 0)

        malicious_count = stats.get("malicious", 0)
        suspicious_count = stats.get("suspicious", 0)

        if malicious_count >= 5:
            verdict = "MALICIOUS"
        elif malicious_count > 0 or suspicious_count > 0:
            verdict = "SUSPICIOUS"
        else:
            verdict = "CLEAN"

        return {
            "hash": hash_value,
            "status": "found",
            "verdict": verdict,
            "file_name": primary_name,
            "file_type": file_type,
            "reputation": reputation,
            "threat_label": popular_category,
            "stats": stats,
        }

    if status_code == 404:
        return {
            "hash": hash_value,
            "status": "not_found",
            "verdict": "UNKNOWN",
            "message": "Hash was not found in VirusTotal database.",
        }

    if status_code == 401:
        return {
            "hash": hash_value,
            "status": "error",
            "message": "Authentication failed. Check if your API key is valid.",
        }

    if status_code == 429:
        return {
            "hash": hash_value,
            "status": "error",
            "message": "Rate limit exceeded. VirusTotal Public API allows up to 4 requests/min.",
        }

    return {
        "hash": hash_value,
        "status": "error",
        "message": f"Unexpected HTTP status code: {status_code}",
    }


def print_triage_result(result: Dict[str, Any]) -> None:
    """
    Renders human-readable summary of query results in standard terminal text format.
    """
    print("\n" + "=" * 60)
    print(f"Target Hash : {result['hash']}")
    print("-" * 60)

    status = result.get("status")

    if status == "error":
        print(f"[ERROR] {result.get('message')}")
        print("=" * 60)
        return

    if status == "not_found":
        print("[INFO] Status  : Not Found")
        print("[INFO] Verdict : UNKNOWN (Artifact has not been submitted to VirusTotal)")
        print("=" * 60)
        return

    verdict = result.get("verdict")
    tag = "[ALERT]" if verdict == "MALICIOUS" else "[WARN]" if verdict == "SUSPICIOUS" else "[OK]"

    stats = result.get("stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)
    total_engines = malicious + suspicious + harmless + undetected

    print(f"Verdict     : {tag} {verdict}")
    print(f"File Name   : {result.get('file_name')}")
    print(f"File Type   : {result.get('file_type')}")
    print(f"Threat Label: {result.get('threat_label')}")
    print(f"Reputation  : {result.get('reputation')}")
    print("-" * 60)
    print(f"Detections  : {malicious}/{total_engines} engines flagged as malicious")
    print(f"Breakdown   : Malicious: {malicious} | Suspicious: {suspicious} | Harmless: {harmless} | Undetected: {undetected}")
    print("=" * 60)


def load_hashes_from_file(file_path: str) -> List[str]:
    """
    Reads a text file containing one hash per line, filtering comments and blank lines.
    """
    if not os.path.isfile(file_path):
        print(f"[ERROR] Target file not found: {file_path}")
        sys.exit(1)

    hashes = []
    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            clean_line = line.strip()
            if clean_line and not clean_line.startswith("#"):
                hashes.append(clean_line)
    return hashes


def parse_arguments() -> argparse.Namespace:
    """Configures command line flags and help parameters."""
    parser = argparse.ArgumentParser(
        description="VirusTotal Hash Triage Automation Tool for SOC & Incident Response",
        epilog="Example: python hash_triage.py --hash 44d88612fea8a8f36de82e1278abb02f"
    )
    parser.add_argument(
        "-H", "--hash",
        dest="target_hash",
        help="Single MD5, SHA-1, or SHA-256 hash to analyze"
    )
    parser.add_argument(
        "-f", "--file",
        dest="file_path",
        help="Path to a text file containing a list of hashes (one per line)"
    )
    parser.add_argument(
        "-k", "--key",
        dest="api_key",
        help="VirusTotal API Key (optional if VT_API_KEY environment variable is set)"
    )
    parser.add_argument(
        "-o", "--export",
        dest="export_path",
        help="Optional path to export results as a JSON report"
    )
    return parser.parse_args()


def main() -> None:
    args = parse_arguments()
    api_key = get_api_key(args.api_key)

    hashes_to_query: List[str] = []

    if args.target_hash:
        hashes_to_query.append(args.target_hash.strip())
    elif args.file_path:
        hashes_to_query.extend(load_hashes_from_file(args.file_path))
    else:
        interactive_hash = input("Enter file hash to query (MD5/SHA-1/SHA-256): ").strip()
        if interactive_hash:
            hashes_to_query.append(interactive_hash)
        else:
            print("[ERROR] No hash provided. Exiting.")
            sys.exit(1)

    all_results: List[Dict[str, Any]] = []

    for item in hashes_to_query:
        hash_type = validate_hash_format(item)
        if not hash_type:
            print(f"\n[ERROR] Invalid hash structure: '{item}'. Skipping.")
            all_results.append({
                "hash": item,
                "status": "error",
                "message": "Invalid hash structure (must be MD5, SHA-1, or SHA-256 hex string).",
            })
            continue

        print(f"\n[INFO] Querying VirusTotal for {hash_type}: {item}...")
        result = query_virustotal(item, api_key)
        all_results.append(result)
        print_triage_result(result)

    if args.export_path:
        try:
            with open(args.export_path, "w", encoding="utf-8") as out:
                json.dump(all_results, out, indent=2)
            print(f"\n[INFO] Triage results exported to JSON: {args.export_path}")
        except IOError as exc:
            print(f"\n[ERROR] Failed to export JSON report: {exc}")


if __name__ == "__main__":
    main()
