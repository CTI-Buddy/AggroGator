# Threat Intelligence Aggregator

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
