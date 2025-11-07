# 🔍 Valak - Unified Security Scanner Suite

**Valak** is a comprehensive, all-in-one security scanning tool that combines multiple security utilities into a single, cohesive application. Perfect for penetration testers, security researchers, and system administrators.

![Version](https://img.shields.io/badge/version-1.0-blue)
![Python](https://img.shields.io/badge/python-3.9+-green)
![License](https://img.shields.io/badge/license-MIT-orange)

---

## ✨ Features

### 🔍 **IP Vulnerability Scanner**
- Scan IP addresses for vulnerabilities using Shodan InternetDB API
- Detect open ports, CVEs, hostnames, and technologies
- Support for CIDR ranges, domain resolution, and file-based targets
- Multiple output formats: JSONL, CSV, XML, HTML
- SQLite database for scan history
- **Advanced bypass system** for rate limit evasion

### 🌐 **DNS to IP Resolution**
- Resolve domain names to IP addresses
- Support for IPv4 and IPv6
- Multi-threaded for fast resolution
- Batch processing from files

### 🔎 **Subdomain Enumeration**
- Passive collection from Certificate Transparency (crt.sh)
- Brute force enumeration with wordlists
- DNS validation (A/AAAA records)
- Optional HTTP inventory
- Multi-threaded for performance

### 🔨 **Directory & VHost Fuzzing**
- Directory enumeration with custom wordlists
- Virtual host discovery
- Custom status code filtering
- Extension testing
- Async/await for high performance

### 📊 **CSV Domain Extraction**
- Extract domains from CSV files
- Support for URLs and email addresses
- Automatic delimiter detection
- Column selection support

---

## 📦 Installation

### Prerequisites
- Python 3.9 or higher
- pip (Python package manager)

### Quick Install

```bash
# Clone or download the repository
cd Valak

# Install dependencies
pip install -r requirements.txt
```

### Dependencies
- `requests` - HTTP library
- `aiohttp` - Async HTTP client
- `aiodns` - Async DNS resolver
- `dnspython` - DNS toolkit

---

## 🚀 Quick Start

### Scan IP Addresses

```bash
# Single IP scan
python valak.py scan --ip 8.8.8.8

# Scan from file
python valak.py scan --file targets.txt --csv results.csv

# With bypass system (recommended for large scans)
python valak.py scan --file targets.txt --bypass --bypass-rpm 30

# Generate HTML report
python valak.py scan --file targets.txt --html report.html
```

### Resolve Domains to IPs

```bash
# Resolve domains from file
python valak.py resolve --input dns.txt --output ip.txt

# Include IPv6 addresses
python valak.py resolve --input dns.txt --output ip.txt --ipv6
```

### Enumerate Subdomains

```bash
# Passive collection (Certificate Transparency)
python valak.py subdomain passive -d example.com -o out

# Brute force with wordlist
python valak.py subdomain brute -d example.com -w wordlist.txt -o out

# Validate existing subdomain list
python valak.py subdomain validate -i subs.txt -o out --http
```

### Fuzz Directories

```bash
# Directory enumeration
python valak.py fuzz dir -u https://target.com -w wordlist.txt

# Virtual host discovery
python valak.py fuzz vhost -u https://target.com -b 192.168.1.1 -w wordlist.txt
```

### Extract Domains from CSV

```bash
# Extract from CSV file
python valak.py extract --input data.csv --output domains.txt

# Extract from specific columns
python valak.py extract --input data.csv --output domains.txt --columns email website
```

---

## 📖 Detailed Usage

### Scan Module

```bash
python valak.py scan [OPTIONS]

Target Options:
  -f, --file FILE          File containing IP list (IPs or CIDR)
  --dns-file FILE          File containing domain names
  --ip IP                  Single IP to scan
  --cidr CIDR              CIDR range to scan (e.g., 192.168.1.0/24)
  --domain DOMAIN          Domain to resolve and scan

Output Options:
  --cves                   Show CVEs only
  --ports                  Show open ports only
  --host                   Show hostnames only
  --jsonl FILE             Output JSONL file
  --csv FILE               Output CSV file
  --xml FILE               Output XML file
  --html FILE              Output HTML report

Scan Options:
  -t, --threads N          Number of threads (default: 10)
  --timeout N              Request timeout in seconds (default: 5)
  --delay N                Delay between requests (default: 0.1)
  --rps N                  Requests per second limit
  --db FILE                SQLite database path for scan history
  --geolocation             Enable IP geolocation lookup
  --webhook URL            Webhook URL for critical findings
  --show-stats              Show statistics at end

Bypass Options:
  --bypass                  Enable bypass system for rate limits
  --bypass-sessions N       Number of sessions (default: 10)
  --bypass-rpm N            Requests per minute (default: 30)
  --bypass-cache FILE       Cache file (default: shodan_cache.json)
  --bypass-cache-hours N    Cache validity hours (default: 24)
  --bypass-min-delay N      Minimum delay between requests (default: 1.0)
  --bypass-max-delay N      Maximum delay between requests (default: 3.0)
  --proxy-file FILE         File with proxy list for bypass
```

### Resolve Module

```bash
python valak.py resolve [OPTIONS]

  -i, --input FILE         Input file with domains (default: dns.txt)
  -o, --output FILE        Output file for IPs (default: ip.txt)
  -t, --workers N          Number of workers (default: 10)
  --ipv6                   Include IPv6 addresses
```

### Subdomain Module

```bash
python valak.py subdomain {passive|brute|validate} [OPTIONS]

Passive Mode:
  -d, --domain DOMAIN      Domain to enumerate (required)
  -o, --out DIR            Output directory (default: out)
  -t, --threads N          Concurrency (default: 200)
  --resolvers FILE         File with DNS resolvers
  --http                   Perform HTTP inventory

Brute Mode:
  -d, --domain DOMAIN      Domain to enumerate (required)
  -w, --wordlist FILE      Wordlist file (required)
  -o, --out DIR            Output directory
  -t, --threads N          Concurrency
  --resolvers FILE         File with DNS resolvers
  --http                   Perform HTTP inventory

Validate Mode:
  -i, --input FILE         Input file with subdomains (required)
  -o, --out DIR            Output directory
  -t, --threads N          Concurrency
  --resolvers FILE         File with DNS resolvers
  --http                   Perform HTTP inventory
```

### Fuzz Module

```bash
python valak.py fuzz {dir|vhost} [OPTIONS]

Directory Mode:
  -u URL                   Base URL (required)
  -w FILE                  Wordlist file (required)
  -t N                     Concurrency (default: 50)
  -S CODES                 Status codes to show (default: 200,204,301,302,307,401,403)
  -e EXTS                  Extensions (comma-separated, e.g., php,html,js)
  --timeout N              Timeout in seconds (default: 15)
  --ua STRING              User-Agent string (default: Valak/1.0)

VHost Mode:
  -u URL                   Target URL (required)
  -b IP                    Base IP address (required)
  -w FILE                  Wordlist file (required)
  --domain DOMAIN          Domain (auto-extracted from URL if not provided)
  -t N                     Concurrency
  -S CODES                 Status codes
  --timeout N              Timeout
  --ua STRING              User-Agent
```

### Extract Module

```bash
python valak.py extract [OPTIONS]

  --input FILE             Input CSV file (required)
  --output FILE            Output file for domains (required)
  --columns COLUMNS        Columns to check (names or indices, optional)
```

---

## 🎯 Advanced Usage

### Bypass System for Large Scans

The bypass system helps evade rate limits for large-scale scanning:

```bash
# Conservative (recommended for 1000+ IPs)
python valak.py scan --file large_targets.txt --bypass \
  --bypass-rpm 20 \
  --bypass-sessions 15 \
  --bypass-min-delay 2.0 \
  --bypass-max-delay 5.0

# With proxies (best for very large scans)
python valak.py scan --file huge_targets.txt --bypass \
  --proxy-file proxies.txt \
  --bypass-rpm 30
```

**Bypass System Features:**
- ✅ Multiple session rotation (10-20 sessions)
- ✅ User agent rotation (16+ realistic browsers)
- ✅ Intelligent caching (reduces API calls by 50-80%)
- ✅ Adaptive rate limiting (20-50 RPM configurable)
- ✅ Automatic 429 error recovery
- ✅ Proxy support for IP rotation

See `BYPASS_ANALYSIS.md` for detailed effectiveness analysis.

### Complete Workflow Example

```bash
# 1. Extract domains from CSV
python valak.py extract --input data.csv --output domains.txt

# 2. Resolve domains to IPs
python valak.py resolve --input domains.txt --output targets.txt

# 3. Scan IPs with bypass system
python valak.py scan --file targets.txt --bypass --bypass-rpm 25 \
  --csv results.csv --html report.html

# 4. Enumerate subdomains
python valak.py subdomain passive -d example.com -o subdomains

# 5. Fuzz discovered subdomains
python valak.py fuzz dir -u https://subdomain.example.com -w wordlist.txt
```

---

## 📁 Project Structure

```
Valak/
├── valak.py                 # Main entry point
├── modules/
│   ├── __init__.py
│   ├── scanner.py          # IP vulnerability scanner
│   ├── bypass_system.py    # Rate limit bypass system
│   ├── dns_resolver.py     # DNS to IP resolution
│   ├── subdomain_enum.py  # Subdomain enumeration
│   ├── fuzzer.py           # Directory/VHost fuzzing
│   └── csv_extractor.py    # CSV domain extraction
├── requirements.txt        # Python dependencies
├── README.md              # This file
├── BYPASS_ANALYSIS.md     # Bypass system analysis
└── .gitignore            # Git ignore rules
```

---

## 📊 Output Files

### Scanner Output
- `results.jsonl` - JSON Lines format (one JSON object per line)
- `results.csv` - CSV format with headers
- `report.xml` - XML format with structured data
- `report.html` - Styled HTML report with color coding
- `scans.db` - SQLite database (if `--db` used)
- `shodan_cache.json` - Bypass system cache

### Subdomain Output (in `out/` directory)
- `subs_raw.txt` - Raw subdomain names
- `subs_resolved.txt` - Validated subdomains with IPs (format: `host ip1 ip2 ...`)
- `web_hosts.txt` - HTTP inventory (if `--http` used, format: `url code title`)

---

## ⚙️ Configuration

### Recommended Settings

**Small Scans (< 100 IPs):**
```bash
python valak.py scan --file targets.txt --bypass --bypass-rpm 50
```

**Medium Scans (100-1000 IPs):**
```bash
python valak.py scan --file targets.txt --bypass \
  --bypass-rpm 30 \
  --bypass-sessions 15
```

**Large Scans (1000+ IPs):**
```bash
python valak.py scan --file targets.txt --bypass \
  --bypass-rpm 20 \
  --bypass-sessions 20 \
  --bypass-min-delay 2.0 \
  --bypass-max-delay 5.0 \
  --proxy-file proxies.txt
```

---

## 🔧 Troubleshooting

### Common Issues

**1. ModuleNotFoundError**
```bash
# Solution: Install dependencies
pip install -r requirements.txt
```

**2. File Not Found Errors**
```bash
# Solution: Create required files or specify correct paths
# Example: Create dns.txt with domains
echo "example.com" > dns.txt
```

**3. Rate Limiting**
```bash
# Solution: Use bypass system with lower RPM
python valak.py scan --file targets.txt --bypass --bypass-rpm 20
```

**4. Encoding Issues (Windows)**
- Already handled automatically in the code
- If issues persist, set environment variable: `PYTHONIOENCODING=utf-8`

---

## 📝 Examples

### Example 1: Quick IP Scan
```bash
python valak.py scan --ip 8.8.8.8 --ports --host
```

### Example 2: Batch Scan with Reports
```bash
python valak.py scan --file targets.txt \
  --csv results.csv \
  --html report.html \
  --xml report.xml \
  --show-stats
```

### Example 3: Subdomain Discovery
```bash
# Passive discovery
python valak.py subdomain passive -d example.com -o out --http

# Brute force
python valak.py subdomain brute -d example.com -w wordlist.txt -o out
```

### Example 4: Directory Fuzzing
```bash
python valak.py fuzz dir \
  -u https://target.com \
  -w wordlist.txt \
  -e php,html,js \
  -S 200 301 302 403
```

---

## 🛡️ Security & Legal

**⚠️ IMPORTANT:**
- Use this tool only on systems you own or have explicit permission to test
- Unauthorized scanning is illegal in many jurisdictions
- Always comply with applicable laws and regulations
- The authors are not responsible for misuse of this tool

---

## 🤝 Contributing

This is a unified security tool combining multiple utilities. Each module can be used independently or as part of the complete suite.

---

## 📄 License

Use responsibly and only on systems you own or have permission to test.

---

## 🎓 Tips & Best Practices

1. **Use Bypass System for Large Scans**: Enable `--bypass` for scans with 100+ IPs
2. **Lower RPM for Reliability**: Use 20-30 RPM for large scans instead of 50
3. **Enable Caching**: Bypass system caches results for 24 hours by default
4. **Use Proxies**: For very large scans (1000+ IPs), use proxy rotation
5. **Adjust Threads**: More threads = faster but more aggressive
6. **Save Results**: Always use `--csv` or `--jsonl` to save scan results
7. **Review HTML Reports**: HTML reports provide visual overview of findings

---

## 📚 Additional Documentation

- `BYPASS_ANALYSIS.md` - Detailed bypass system effectiveness analysis
- `FIXES_APPLIED.md` - List of all bugs fixed and improvements made

---

## 🐛 Known Limitations

- Shodan InternetDB has rate limits (bypass system helps but doesn't eliminate them)
- Without proxies, all requests come from same IP
- Large scans take time (bypass system adds delays to avoid rate limits)
- Some modules require internet connection

---

## 💡 Notes

- The bypass system is effective for more scans but requires tuning (see `BYPASS_ANALYSIS.md`)
- Recommended RPM: 20-30 for large scans, 40-50 for small scans
- Caching can reduce API calls by 50-80% on repeated scans
- Proxies significantly improve effectiveness for very large scans

---

## 📞 Support

For issues, questions, or contributions, please refer to the project documentation or create an issue in the repository.

---

**Made with ❤️ for the security community**
