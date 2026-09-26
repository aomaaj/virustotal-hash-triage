#!/usr/bin/env python3
"""
VirusTotal Hash Triage Tool
Script para consulta e triagem de hashes utilizando a API v3 do VirusTotal.
"""

import argparse
import os
import re
import sys
from typing import Any, Dict, Optional
import urllib.error
import urllib.request

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
    for hash_type, pattern in HASH_REGEX.items():
        if pattern.match(hash_value):
            return hash_type
    return None


def get_api_key(cli_key: Optional[str] = None) -> str:
    if cli_key:
        return cli_key.strip()

    env_key = os.getenv("VT_API_KEY")
    if env_key:
        return env_key.strip()

    if os.path.isfile(".env"):
        with open(".env", "r", encoding="utf-8") as env_file:
            for line in env_file:
                clean = line.strip()
                if clean.startswith("VT_API_KEY="):
                    val = clean.split("=", 1)[1].strip().strip('"').strip("'")
                    if val and val != "your_virustotal_api_key_here":
                        return val

    prompt_key = input("Digite sua chave de API do VirusTotal: ").strip()
    if not prompt_key:
        print("[ERRO] Chave de API necessaria.")
        sys.exit(1)
    return prompt_key


def query_virustotal(hash_value: str, api_key: str) -> Dict[str, Any]:
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
            import json
            data_json = json.loads(response_body)
    except urllib.error.HTTPError as http_err:
        status_code = http_err.code
        data_json = {}
    except Exception as exc:
        return {
            "hash": hash_value,
            "status": "error",
            "message": f"Erro de comunicacao: {exc}",
        }

    if status_code == 200:
        data = data_json.get("data", {})
        attributes = data.get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        threat_class = attributes.get("popular_threat_classification", {})

        popular_category = threat_class.get("suggested_threat_label", "N/A")
        file_names = attributes.get("names", [])
        primary_name = file_names[0] if file_names else "Desconhecido"
        file_type = attributes.get("type_description", "Desconhecido")
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
            "message": "Hash nao encontrado na base do VirusTotal.",
        }

    return {
        "hash": hash_value,
        "status": "error",
        "message": f"Codigo HTTP inesperado: {status_code}",
    }


def print_triage_result(result: Dict[str, Any]) -> None:
    print("\n" + "=" * 60)
    print(f"Hash Alvo   : {result['hash']}")
    print("-" * 60)

    if result.get("status") != "found":
        print(f"Status      : {result.get('status')}")
        print(f"Mensagem    : {result.get('message', '')}")
        print("=" * 60)
        return

    verdict = result.get("verdict")
    tag = "[ALERT]" if verdict == "MALICIOUS" else "[WARN]" if verdict == "SUSPICIOUS" else "[OK]"
    stats = result.get("stats", {})
    malicious = stats.get("malicious", 0)
    total = sum(stats.values()) if stats else 0

    print(f"Veredito    : {tag} {verdict}")
    print(f"Nome        : {result.get('file_name')}")
    print(f"Tipo        : {result.get('file_type')}")
    print(f"Rotulo      : {result.get('threat_label')}")
    print(f"Deteccoes   : {malicious}/{total} motores reportaram como malicioso")
    print("=" * 60)


def main() -> None:
    parser = argparse.ArgumentParser(description="Triagem de hashes via VirusTotal")
    parser.add_argument("-H", "--hash", dest="target_hash", help="Hash para consulta")
    parser.add_argument("-k", "--key", dest="api_key", help="Chave de API")
    args = parser.parse_args()

    api_key = get_api_key(args.api_key)
    target = args.target_hash or input("Digite o hash (MD5/SHA-1/SHA-256): ").strip()

    if not target:
        print("[ERRO] Nenhum hash informado.")
        sys.exit(1)

    hash_type = validate_hash_format(target)
    if not hash_type:
        print(f"[ERRO] Formato de hash invalido: {target}")
        sys.exit(1)

    print(f"[INFO] Consultando VirusTotal para {hash_type}: {target}...")
    res = query_virustotal(target, api_key)
    print_triage_result(res)


if __name__ == "__main__":
    main()