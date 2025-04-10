
# AggroGator
![image](https://github.com/user-attachments/assets/eb795fbb-4954-41ae-8fbe-61a449be20bb)


![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

A Python tool that aggregates and correlates threat intelligence from multiple sources including ThreatFox (Abuse.ch), Hybrid Analysis, and VirusTotal. The tool fetches recent IOCs, enriches them with additional context, and generates comprehensive reports.

## Features

- **Multi-source Intelligence Gathering**:
  - ThreatFox (Abuse.ch) for recent IOCs
  - Hybrid Analysis for sandbox detonations
  - VirusTotal for reputation checks

- **Advanced Processing**:
  - IOC correlation across sources
  - Parallel API requests for faster processing
  - Data enrichment with detonation details

- **Flexible Output**:
  - CSV or JSON export
  - Consolidated view of all intelligence

## Requirements

- Python 3.8+
- Required packages:
  ```bash
  pip install requests pandas concurrent-log-handler
  ```

## API Keys

You'll need the following API keys:

1. **Hybrid Analysis**: Get from [Hybrid Analysis API Keys](https://www.hybrid-analysis.com/apikeys)
2. **VirusTotal**: Get from [VirusTotal API](https://www.virustotal.com/gui/my-apikey)

Add these to the configuration section at the top of the script.

## Usage

```bash
python threat_intel_aggregator.py
```

The script will:
1. Fetch recent IOCs from ThreatFox
2. Get latest submissions from Hybrid Analysis
3. Enrich data with detonation reports
4. Check all IOCs against VirusTotal
5. Generate a consolidated report (`threat_intel_report.csv`)

## Output Example

| ioc_value | ioc_type | threat_type | malware | sources | malicious | reputation |
|-----------|----------|-------------|---------|---------|-----------|------------|
| a1b2c3... | sha256   | malware     | Emotet  | ThreatFox\|HybridAnalysis | 58 | 85 |

## Configuration

Customize these variables in the script:

```python
# API endpoints
THREATFOX_URL = "https://threatfox.abuse.ch/export/json/recent/"
HA_QUICK_SCAN_URL = "https://www.hybrid-analysis.com/api/v2/feed/quick-scan"
HA_DETONATION_URL = "https://www.hybrid-analysis.com/api/v2/feed/detonation/{}"

# API keys (replace with your own)
HA_API_KEY = "your_ha_api_key"
VT_API_KEY = "your_vt_api_key"
```

## Rate Limiting

The script handles API rate limits by:
- 15-second delay between VirusTotal requests
- Thread pooling for Hybrid Analysis requests
- Error handling for API limits

## License

MIT License - see [LICENSE](LICENSE) for details.

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

