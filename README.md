<p align="center">
  <h1 align="center">⚔️ TSURUGI v3.0</h1>
  <p align="center">
    <strong>Offensive Web Security Framework</strong>
  </p>
  <p align="center">
    <em>Detect. Verify. Exploit.</em>
  </p>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-3.0-red?style=for-the-badge" alt="Version">
  <img src="https://img.shields.io/badge/python-3.8+-blue?style=for-the-badge&logo=python" alt="Python">
  <img src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20Mac-lightgrey?style=for-the-badge" alt="Platform">
  <img src="https://img.shields.io/badge/license-MIT-green?style=for-the-badge" alt="License">
</p>

---

## 🎯 What is Tsurugi?

**Tsurugi** (剣 - Japanese for "sword") is a modular offensive security framework for Bug Bounty hunters and penetration testers. Unlike basic scanners, Tsurugi **confirms vulnerabilities** before reporting them.

### Key Differentiators

| Feature | Basic Scanners | Tsurugi v3.0 |
|---------|---------------|--------------|
| XSS Detection | Pattern matching | ✅ **Browser-confirmed** (zero false positives) |
| Secret Detection | Regex only | ✅ **API-verified** (tests if keys work) |
| DOM XSS | ❌ Not supported | ✅ **Static JS analysis** |
| CVE Scanning | Limited | ✅ **6000+ Nuclei templates** |
| Hidden Params | ❌ Not supported | ✅ **100+ param fuzzing** |

---

## 🚀 Features

### Vulnerability Scanners
- **SQLi** — Error-based + Time-based blind with dynamic threshold
- **XSS** — Reflected + Blind (OOB) + **Headless Confirmation**
- **LFI** — Path traversal with encoding bypass
- **SSTI** — Jinja2, Twig, Freemarker, Velocity, Smarty, Mako
- **Secrets** — 30+ patterns (AWS, Stripe, GitHub, JWT...) with **active verification**

### v3.0 New Modules
- **DOM XSS** — Static JavaScript analysis (sinks/sources)
- **Params** — Hidden parameter discovery
- **Nuclei** — Integration with 6000+ vulnerability templates

### Recon & Automation
- **Crawler** — Discovers endpoints, forms, JS routes
- **Hunter** — Automated subfinder → nuclei pipeline
- **Mass Scan** — Multi-threaded batch scanning

### Evasion & Stealth
- **Cloudflare Bypass** — cloudscraper + playwright-stealth
- **Stealth Mode** — Timing delays + header randomization
- **Proxy Support** — Route through Burp/ZAP

---

## 📦 Installation

```bash
git clone https://github.com/HikariSystem/TSURUGI.git
cd TSURUGI
pip install -r requirements.txt

# For headless features (--confirm, --heavy, --cf-bypass)
playwright install chromium
```

**Optional dependencies:**
- `nuclei` — For CVE scanning ([install](https://docs.projectdiscovery.io/tools/nuclei/install))
- `subfinder` — For subdomain enumeration

---

## 🗡️ Quick Start

### Scan for SQL Injection
```bash
python tsurugi.py attack "http://target.com/page?id=1"
```

### XSS with Browser Confirmation
```bash
python tsurugi.py xss "http://target.com/search?q=test" --confirm
```

### Find Hidden Parameters
```bash
python tsurugi.py params "http://target.com/api/user"
```

### DOM XSS Analysis
```bash
python tsurugi.py domxss "http://target.com"
```

### Scan for CVEs with Nuclei
```bash
python tsurugi.py nuclei "http://target.com" --templates cves,exposures
```

### Detect & Verify Secrets
```bash
python tsurugi.py secrets "http://target.com/app.js" --verify
```

---

## 📋 Full Command Reference

| Command | Description |
|---------|-------------|
| `attack <url>` | SQL Injection scanner |
| `xss <url> [--confirm]` | XSS scanner with optional browser confirmation |
| `lfi <url>` | Local File Inclusion scanner |
| `ssti <url>` | Server-Side Template Injection |
| `secrets <url> [--verify]` | Secret/credential detection |
| `params <url>` | Hidden parameter discovery |
| `domxss <url>` | DOM XSS static analysis |
| `nuclei <url>` | CVE/vuln scan (6000+ templates) |
| `crawl <url>` | Spider for endpoints |
| `hunter <domain>` | Full recon automation |
| `mass_check <file>` | Batch scanning |
| `report` | Generate HTML report |

### Global Flags

| Flag | Description |
|------|-------------|
| `--cookie`, `-c` | Session cookie |
| `--proxy`, `-p` | Proxy URL (Burp, ZAP) |
| `--stealth`, `-s` | Evasion mode |
| `--cf-bypass` | Cloudflare bypass |
| `--oob` | Out-of-band detection |
| `--heavy` | Headless browser mode |

---

## 📁 Output Structure

```
TSURUGI/
├── loot/                    # Vulnerability findings (JSON)
│   ├── sqli_*.json
│   ├── xss_confirmed_*.json
│   ├── secrets_*.json
│   └── screenshots/         # XSS confirmation screenshots
├── reports/                 # HTML reports
└── payloads/                # Custom payload files
```

---

## 🔥 Example Workflow

```bash
# 1. Crawl target for endpoints
python tsurugi.py crawl "https://target.com" --depth 2

# 2. Test for SQLi
python tsurugi.py attack "https://target.com/api?id=1"

# 3. Test for XSS (confirmed in browser)
python tsurugi.py xss "https://target.com/search?q=x" --confirm

# 4. Find hidden parameters
python tsurugi.py params "https://target.com/api/user"

# 5. Scan for CVEs
python tsurugi.py nuclei "https://target.com"

# 6. Generate report
python tsurugi.py report
```

---

## ⚠️ Disclaimer

This tool is intended for **authorized security testing only**. 

Usage against systems without explicit permission is illegal. The authors assume no liability for misuse of this software.

---

<p align="center">
  <strong>Open Source Security Framework by HikariSystem</strong>
</p>
