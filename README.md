<!-- © VampSecure Studios — VampSecure Labs Security Research Division -->
<h1 align="center">vamp-darkweb-intel</h1>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.9%2B-blue?logo=python&logoColor=white" alt="Python 3.9+"/>
  <img src="https://img.shields.io/badge/platform-linux%20%7C%20macOS%20%7C%20windows-lightgrey" alt="Platform"/>
  <img src="https://img.shields.io/badge/license-MIT-green" alt="License MIT"/>
  <img src="https://img.shields.io/badge/VampSecure-Labs-magenta" alt="VampSecure Labs"/>
  <img src="https://img.shields.io/badge/API%20keys-optional-brightgreen" alt="API keys optional"/>
</p>

## Overview

`vamp-darkweb-intel` is a threat intelligence and darkweb research CLI that queries a target (domain, IP, hash, or URL) across multiple public feeds in parallel and **automatically correlates signals from independent sources**. When two or more sources flag the same indicator, the engine escalates severity — a C2 confirmed in both ThreatFox and OTX is more actionable than a single mention.

It works **without any API keys** using a curated set of free public feeds. Optional API keys (OTX, HIBP) unlock higher rate limits and additional data sources.

## Sources

| Source | Type | API key? | Target |
|--------|------|----------|--------|
| ThreatFox (abuse.ch) | IOC / C2 | No | Domain · IP · Hash · URL |
| URLhaus (abuse.ch) | Malware distribution | No | Domain · IP · URL |
| MalwareBazaar (abuse.ch) | Malware samples | No | Hash |
| RansomLook | Ransomware victims | No | Domain |
| Ransomware.live | Ransomware victims (recent) | No | Domain |
| GreyNoise Community | IP context (scanner / malicious) | No | IP |
| Shodan InternetDB | Open ports · CVEs | No | IP |
| AlienVault OTX | Threat intel pulses | Optional | Domain · IP · Hash |
| HackerTarget | IP geolocation | No | IP |
| Have I Been Pwned | Domain breach check | `HIBP_API_KEY` | Domain |

## Features

- Automatic target type detection: domain, IP, MD5/SHA1/SHA256 hash, or URL
- Parallel queries across all relevant sources (configurable workers)
- **Correlation engine**: if ≥2 independent sources flag the same category, severity escalates by one level
- Zero mandatory dependencies — only Python stdlib and `rich`
- Export to Console, JSON, HTML (dark-theme), Markdown, and CSV
- Exit codes suited for CI/CD pipelines (0 = clean, 1 = HIGH, 2 = CRITICAL)

## Requirements

- Python 3.9 or later
- `rich >= 13.7.0`

## Installation

```bash
git clone https://github.com/Vampsecure-Labs/vamp-darkweb-intel.git
cd vamp-darkweb-intel
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

Or via PyPI:

```bash
pip install vamp-darkweb-intel
# o con Homebrew:
brew install vampsecure-labs/labs/vamp-darkweb-intel
```

## Try it now

No setup required — these queries go to public free-tier feeds:

```bash
# Investigate an IP (GreyNoise + Shodan InternetDB + OTX + ThreatFox)
python3 vamp_darkweb_intel.py -t 1.1.1.1

# Check a domain for threat feed presence and ransomware victims
python3 vamp_darkweb_intel.py -t example.com

# Look up a known malware hash
python3 vamp_darkweb_intel.py -t 44d88612fea8a8f36de82e1278abb02f
```

> These targets will show INFO or CLEAN results — they are safe, well-known hosts and hashes used only to demonstrate the tool workflow.

## Examples

```bash
# Single domain investigation
python3 vamp_darkweb_intel.py -t suspicious-domain.com

# Multiple targets in one run
python3 vamp_darkweb_intel.py -t 185.220.101.1 -t evil-corp.biz

# Bulk investigation from file
python3 vamp_darkweb_intel.py --file iocs.txt --workers 10

# Force target type (useful for ambiguous inputs)
python3 vamp_darkweb_intel.py -t abc123def456... --type hash

# Export full results to all formats
python3 vamp_darkweb_intel.py -t 192.0.2.1 \
    --json results.json \
    --html report.html \
    --markdown report.md \
    --csv report.csv
```

## Optional API keys

Set these environment variables before running to unlock additional sources:

```bash
export OTX_API_KEY=your_key_here       # AlienVault OTX — extended rate limit
export HIBP_API_KEY=your_key_here      # Have I Been Pwned domain breach check
```

Copy `.env.example` to `.env` and fill in the keys you have:

```bash
cp .env.example .env
```

## Correlation engine

The engine cross-references findings by category across all sources. When two or more independent sources report the same finding category for a target, the highest-severity finding in that category is escalated by one level (up to CRITICAL).

**Example**: if ThreatFox reports `Threat Feed / MEDIUM` (confidence 50%) and OTX reports the same domain in 4 pulses (`Threat Intelligence / LOW`), the correlation engine adds a `MEDIUM → HIGH` escalated finding with a note listing both sources.

This reduces noise from low-confidence single-source hits while surfacing genuine threats confirmed by independent intelligence.

## CI/CD Integration

```yaml
name: Threat Intelligence Check
on:
  schedule:
    - cron: '0 8 * * 1'
  workflow_dispatch:

jobs:
  darkweb-intel:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: '3.12' }
      - run: pip install vamp-darkweb-intel
      - run: |
          vamp-darkweb-intel \
            -t yourdomain.com \
            --json intel-results.json \
            --markdown intel-report.md
        # Exit 1 = HIGH findings, exit 2 = CRITICAL findings
        env:
          OTX_API_KEY: ${{ secrets.OTX_API_KEY }}
          HIBP_API_KEY: ${{ secrets.HIBP_API_KEY }}
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: intel-report
          path: intel-report.md
```

## CLI Reference

| Flag | Default | Description |
|------|---------|-------------|
| `-t / --target TARGET` | — | Investigation target: domain, IP, hash, or URL (repeatable) |
| `--file FILE` | — | Text file with one target per line |
| `--type TYPE` | auto | Force target type: `domain`, `ip`, `hash`, `url`, `email` |
| `--timeout N` | 12 | Per-source request timeout in seconds |
| `--workers N` | 6 | Parallel source queries |
| `--json FILE` | — | Export results to JSON |
| `--html FILE` | — | Export dark-theme HTML report |
| `--markdown FILE` | — | Export Markdown report |
| `--csv FILE` | — | Export CSV results |

## Exit Codes

| Code | Meaning | CI/CD Behavior |
|------|---------|----------------|
| `0` | Clean — no HIGH or CRITICAL findings | Pipeline passes |
| `1` | HIGH-severity findings detected | Pipeline fails — review required |
| `2` | CRITICAL findings detected | Pipeline fails — immediate action required |

## Severity levels

| Level | Examples |
|-------|---------|
| CRITICAL | Active C2/botnet confirmed · malware hash confirmed · CVEs on exposed service |
| HIGH | IOC in threat feed · ransomware victim confirmed · IP classified malicious |
| MEDIUM | Low-confidence IOC · IP active scanner · multi-source correlation upgrade |
| LOW | Mentioned in old intelligence · minor open port surface |
| INFO | Geolocation data · known-good infrastructure (RIOT) |

## Legal Notice

Use exclusively on systems you own or for which you hold explicit written authorization from the system owner. VampSecure Studios assumes no liability for unauthorized use.

## Part of VampSecure Labs Toolkit

`vamp-darkweb-intel` is part of the VampSecure Labs security research toolkit.

- Portfolio: [github.com/belky-me](https://github.com/belky-me)
- Orchestrator: [github.com/belky-me/vamp-orchestrator](https://github.com/belky-me/vamp-orchestrator)

---

© VampSecure Studios — VampSecure Labs Security Research Division

## Versión
v1.0.0 — VampSecure Labs Security Research Division
