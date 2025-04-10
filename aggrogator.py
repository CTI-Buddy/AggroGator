import requests
import pandas as pd
import time
from hybridanalysis import HybridAnalysis

# --- Configuration ---
THREATFOX_URL = "https://threatfox.abuse.ch/export/json/recent/"
HA_API_KEY = "your_hybrid_analysis_api_key"  # Get from https://www.hybrid-analysis.com/signup
VT_API_KEY = "your_virustotal_api_key"      # Get from https://www.virustotal.com/gui/my-apikey

# --- Fetch ThreatFox IOCs ---
def fetch_threatfox():
    """Fetch recent malware IOCs from ThreatFox."""
    response = requests.get(THREATFOX_URL).json()
    return pd.DataFrame(response["data"])

# --- Fetch Hybrid Analysis Submissions ---
def fetch_ha_recent(limit=20):
    """Fetch recent malicious files from Hybrid Analysis."""
    ha = HybridAnalysis(api_key=HA_API_KEY)
    submissions = ha.get_recent_submissions(limit=limit)
    return pd.DataFrame([{
        "sha256": sub["sha256"],
        "threat_level": sub["threat_level"],
        "malware_family": sub.get("vx_family", "Unknown")
    } for sub in submissions["data"]])

# --- Correlate Data (Find Common Malware) ---
def correlate_threats(tf_data, ha_data):
    """Find malware families present in both ThreatFox and Hybrid Analysis."""
    tf_malware = set(tf_data["malware"].dropna().unique())
    ha_malware = set(ha_data["malware_family"].dropna().unique())
    common_malware = tf_malware.intersection(ha_malware)
    
    # Get SHA256 hashes for common malware families
    common_hashes = ha_data[ha_data["malware_family"].isin(common_malware)]["sha256"].tolist()
    return common_hashes

# --- Bulk Check SHA256 Hashes in VirusTotal ---
def check_virustotal_bulk(sha256_list):
    """Check all SHA256 hashes against VirusTotal (with rate limiting)."""
    results = []
    headers = {"x-apikey": VT_API_KEY}
    
    for sha256 in sha256_list:
        try:
            url = f"https://www.virustotal.com/api/v3/files/{sha256}"
            response = requests.get(url, headers=headers).json()
            
            # Extract key details
            attributes = response.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            results.append({
                "sha256": sha256,
                "malicious": stats.get("malicious", 0),
                "undetected": stats.get("undetected", 0),
                "vendors": ", ".join([
                    k for k, v in attributes.get("last_analysis_results", {}).items() 
                    if v.get("result") == "malicious"
                ]),
                "malware_family": ha_data[ha_data["sha256"] == sha256]["malware_family"].iloc[0]
            })
            time.sleep(15)  # Rate limit: 4 requests/minute (VT free tier)
        
        except Exception as e:
            print(f"[!] Error checking {sha256}: {e}")
    
    return pd.DataFrame(results)

# --- Export Results ---
def export_data(df, filename="threat_intel_report.csv"):
    """Export DataFrame to CSV/JSON."""
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
    ha_data = fetch_ha_recent()
    
    print("[+] Correlating threats...")
    common_hashes = correlate_threats(tf_data, ha_data)
    
    if not common_hashes:
        print("[!] No overlapping malware families found.")
    else:
        print(f"[+] Found {len(common_hashes)} hashes to check in VirusTotal...")
        vt_results = check_virustotal_bulk(common_hashes)
        
        # Merge with Hybrid Analysis data for context
        final_report = pd.merge(
            ha_data[ha_data["sha256"].isin(common_hashes)],
            vt_results,
            on="sha256"
        )
        
        # Export
        export_data(final_report, "threat_intel_report.csv")
        print("\n[+] Final Report:")
        print(final_report[["sha256", "malware_family", "malicious", "vendors"]].head())
