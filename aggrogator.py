import requests
import pandas as pd
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- Configuration ---
THREATFOX_URL = "https://threatfox.abuse.ch/export/json/recent/"
HA_QUICK_SCAN_URL = "https://www.hybrid-analysis.com/api/v2/feed/quick-scan"
HA_DETONATION_URL = "https://www.hybrid-analysis.com/api/v2/feed/detonation/{}"
HA_API_KEY = "hybrid analysis api goes here"
VT_API_KEY = "virustotal api goes here"

# --- Fetch ThreatFox IOCs ---
def fetch_threatfox():
    try:
        response = requests.get(THREATFOX_URL).json()
        ioc_data = []
        for key, values in response.items():
            for value in values:
                ioc_data.append({
                    "ioc_value": value.get("ioc_value"),
                    "ioc_type": value.get("ioc_type"),
                    "threat_type": value.get("threat_type"),
                    "malware": value.get("malware"),
                    "malware_printable": value.get("malware_printable"),
                    "first_seen_utc": value.get("first_seen_utc"),
                    "confidence_level": value.get("confidence_level"),
                    "sources": "ThreatFox"
                })
        return pd.DataFrame(ioc_data)
    except Exception as e:
        print(f"[!] Error fetching ThreatFox IOCs: {e}")
        return pd.DataFrame()

# --- Fetch Hybrid Analysis Quick Scan Feed ---
def fetch_ha_quick_scan(limit=50):
    try:
        headers = {
            "api-key": HA_API_KEY,
            "User-Agent": "Falcon Sandbox"
        }
        response = requests.get(HA_QUICK_SCAN_URL, headers=headers)
        response.raise_for_status()
        data = response.json()
        sliced = data[:limit] if isinstance(data, list) else []
        return pd.DataFrame([{
            "ioc_value": item.get("sha256"),
            "ioc_type": "sha256",
            "submit_name": item.get("submit_name"),
            "size": item.get("size"),
            "mime": item.get("mime"),
            "type": item.get("type"),
            "verdict": item.get("verdict"),
            "verdict_human": item.get("verdict_human"),
            "sources": "HybridAnalysis"
        } for item in sliced if item.get("sha256")])
    except Exception as e:
        print(f"[!] Error fetching HA quick scan feed: {e}")
        return pd.DataFrame()

# --- Enrich HA Data with Detonation Feed ---
def enrich_with_detonation(sha256):
    try:
        url = HA_DETONATION_URL.format(sha256)
        headers = {
            "api-key": HA_API_KEY,
            "User-Agent": "Falcon Sandbox"
        }
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        return {
            "ioc_value": sha256,
            "submit_name": data.get("submit_name"),
            "size": data.get("size"),
            "mime": data.get("mime"),
            "type": data.get("type"),
            "verdict": data.get("verdict"),
            "verdict_human": data.get("verdict_human")
        }
    except Exception as e:
        print(f"[!] Error enriching {sha256}: {e}")
        return {
            "ioc_value": sha256
        }

# --- Check IOC (hash/domain/url) in VirusTotal ---
def check_virustotal_ioc(ioc, ioc_type):
    try:
        if ioc_type == "sha256":
            url = f"https://www.virustotal.com/api/v3/files/{ioc}"
        elif ioc_type == "domain":
            url = f"https://www.virustotal.com/api/v3/domains/{ioc}"
        elif ioc_type == "url":
            url_id = requests.utils.quote(ioc, safe='')
            url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        else:
            return {"ioc_value": ioc, "ioc_type": ioc_type, "sources": "VirusTotal", "malicious": "Unsupported"}

        headers = {"x-apikey": VT_API_KEY}
        response = requests.get(url, headers=headers).json()
        attr = response.get("data", {}).get("attributes", {})
        stats = attr.get("last_analysis_stats", {})

        vt_data = {
            "ioc_value": ioc,
            "ioc_type": ioc_type,
            "malicious": stats.get("malicious", 0),
            "undetected": stats.get("undetected", 0),
            "reputation": attr.get("reputation"),
            "tags": ", ".join(attr.get("tags", [])),
            "first_submission_date": attr.get("first_submission_date"),
            "last_submission_date": attr.get("last_submission_date"),
            "popular_threat_classification": attr.get("popular_threat_classification", {}).get("suggested_threat_label"),
            "sources": "VirusTotal"
        }
        return vt_data
    except Exception as e:
        print(f"[!] VT error for {ioc} ({ioc_type}): {e}")
        return {"ioc_value": ioc, "ioc_type": ioc_type, "sources": "VirusTotal", "malicious": 0, "undetected": 0}

# --- Export Results ---
def export_data(df, filename="threat_intel_report.csv"):
    if filename.endswith(".csv"):
        df.to_csv(filename, index=False)
    elif filename.endswith(".json"):
        df.to_json(filename, orient="records")
    print(f"[+] Exported to {filename}")

# --- Main Workflow ---
if __name__ == "__main__":
    print("[+] Fetching ThreatFox IOCs...")
    tf_data = fetch_threatfox()

    print("[+] Fetching Hybrid Analysis submissions...")
    ha_data = fetch_ha_quick_scan(limit=50)
    if not ha_data.empty:
        print("[+] Enriching with HA detonation data...")
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(enrich_with_detonation, row["ioc_value"]): row["ioc_value"] for _, row in ha_data.iterrows()}
            for future in as_completed(futures):
                result = future.result()
                for k, v in result.items():
                    if k != "ioc_value":
                        ha_data.loc[ha_data["ioc_value"] == result["ioc_value"], k] = v

    print("[+] Cross-referencing all IOCs with VirusTotal...")
    vt_inputs = []
    if not ha_data.empty:
        vt_inputs.extend([(row["ioc_value"], row["ioc_type"]) for _, row in ha_data.iterrows()])
    if not tf_data.empty:
        vt_inputs.extend([(row["ioc_value"], row["ioc_type"]) for _, row in tf_data.iterrows()])

    vt_results = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(check_virustotal_ioc, ioc, ioc_type): (ioc, ioc_type) for ioc, ioc_type in vt_inputs}
        for future in as_completed(futures):
            vt_results.append(future.result())

    vt_df = pd.DataFrame(vt_results)

    all_data = pd.concat([ha_data, tf_data, vt_df], ignore_index=True, sort=False)
    all_data = all_data.groupby(["ioc_value", "ioc_type"], dropna=False).agg(lambda x: '|'.join(sorted(set(str(i) for i in x if pd.notna(i))))).reset_index()

    export_data(all_data, "threat_intel_report.csv")
    print("\n[+] Final Report:")
    print(all_data.head())
