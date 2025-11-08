#!/usr/bin/env python3
"""
Valac - Unified Security Scanner Suite
Combines multiple security tools into one cohesive application:
- IP Vulnerability Scanning (Shodan InternetDB)
- Domain to IP Resolution
- Subdomain Enumeration
- Directory/VHost Fuzzing
- CSV Domain Extraction
"""

import argparse
import sys
import os

# Fix Windows console encoding
if sys.platform == 'win32':
    try:
        import codecs
        sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
        sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')
    except (AttributeError, OSError, ImportError):
        pass

# Import all modules
from modules.scanner import ScannerModule
from modules.dns_resolver import DNSResolverModule
from modules.subdomain_enum import SubdomainEnumModule
from modules.fuzzer import FuzzerModule
from modules.csv_extractor import CSVExtractorModule
from modules.security import SecurityValidator, BlacklistProtection, perform_security_checks

# Color codes
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
BLUE = "\033[94m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
RESET = "\033[0m"

BANNER = f"""{GREEN}

██╗   ██╗ █████╗ ██╗      █████╗  ██████╗
██║   ██║██╔══██╗██║     ██╔══██╗██╔════╝
██║   ██║███████║██║     ███████║██║     
╚██╗ ██╔╝██╔══██║██║     ██╔══██║██║     
 ╚████╔╝ ██║  ██║███████╗██║  ██║╚██████╗
  ╚═══╝  ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝
╔═══════════════════════════════════════╗
║   VALAC - Security Scanner Suite      ║
║   Unified Security Tool v1.0          ║
╚═══════════════════════════════════════╝
{RESET}
{CYAN}        Unified Security Scanner Suite v1.0{RESET}
{YELLOW}        All-in-One Security Tool{RESET}
"""


def print_help():
    """Print detailed help information"""
    print(BANNER)
    print(f"""
{CYAN}Available Modules:{RESET}

{GREEN}1. SCAN{RESET} - IP Vulnerability Scanner
  Scans IP addresses for vulnerabilities, open ports, and security issues
  Uses Shodan InternetDB API

{GREEN}2. RESOLVE{RESET} - DNS to IP Resolution
  Resolves domain names to IP addresses
  Supports IPv4 and IPv6

{GREEN}3. SUBDOMAIN{RESET} - Subdomain Enumeration
  Enumerates subdomains using:
  - Certificate Transparency (crt.sh)
  - Brute force with wordlist
  - DNS validation

{GREEN}4. FUZZ{RESET} - Directory and VHost Fuzzing
  Fuzzes directories and virtual hosts
  Supports custom wordlists and status codes

{GREEN}5. EXTRACT{RESET} - CSV Domain Extraction
  Extracts domains from CSV files
  Supports URLs and email addresses

{CYAN}Usage Examples:{RESET}

  # Scan IP addresses
  python valac.py scan --ip 192.168.1.1
  python valac.py scan --file targets.txt --csv results.csv

  # Resolve domains to IPs
  python valac.py resolve --input dns.txt --output ip.txt

  # Enumerate subdomains
  python valac.py subdomain passive -d example.com -o out
  python valac.py subdomain brute -d example.com -w wordlist.txt

  # Fuzz directories
  python valac.py fuzz dir -u https://target.com -w wordlist.txt

  # Extract domains from CSV
  python valac.py extract --input data.csv --output domains.txt

{CYAN}For detailed help on each module:{RESET}
  python valac.py <module> --help
""")


def main():
    """Main entry point for Valac"""
    parser = argparse.ArgumentParser(
        description="Valac - Unified Security Scanner Suite",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    subparsers = parser.add_subparsers(dest='module', help='Module to run')
    
    # SCAN module
    scan_parser = subparsers.add_parser('scan', help='IP Vulnerability Scanner')
    scan_parser.add_argument("-f", "--file", help="File containing IP list")
    scan_parser.add_argument("--dns-file", help="File containing domain names")
    scan_parser.add_argument("--ip", help="Single IP to scan")
    scan_parser.add_argument("--cidr", help="CIDR range to scan")
    scan_parser.add_argument("--domain", help="Domain to resolve and scan")
    scan_parser.add_argument("--cves", action="store_true", help="Show CVEs")
    scan_parser.add_argument("--ports", action="store_true", help="Show open ports")
    scan_parser.add_argument("--host", action="store_true", help="Show hostnames")
    scan_parser.add_argument("--jsonl", help="Output JSONL file")
    scan_parser.add_argument("--csv", dest="csv_file", help="Output CSV file")
    scan_parser.add_argument("--xml", dest="xml_file", help="Output XML file")
    scan_parser.add_argument("--html", dest="html_file", help="Output HTML report (interactive dashboard)")
    scan_parser.add_argument("--html-simple", dest="html_simple", help="Output simple HTML report (non-interactive)")
    scan_parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads")
    scan_parser.add_argument("--timeout", type=int, default=5, help="Request timeout")
    scan_parser.add_argument("--delay", type=float, default=0.1, help="Delay between requests")
    scan_parser.add_argument("--rps", type=float, help="Requests per second limit")
    scan_parser.add_argument("--db", dest="database", help="SQLite database path")
    scan_parser.add_argument("--geolocation", action="store_true", help="Enable geolocation")
    scan_parser.add_argument("--webhook", help="Webhook URL for critical findings")
    scan_parser.add_argument("--show-stats", action="store_true", help="Show statistics")
    scan_parser.add_argument("--bypass", action="store_true", help="Enable bypass system for rate limits")
    scan_parser.add_argument("--bypass-sessions", type=int, default=10, help="Number of sessions for bypass")
    scan_parser.add_argument("--bypass-rpm", type=int, default=30, help="Requests per minute for bypass (default: 30)")
    scan_parser.add_argument("--bypass-cache", default="shodan_cache.json", help="Cache file for bypass system")
    scan_parser.add_argument("--bypass-cache-hours", type=int, default=24, help="Cache validity hours")
    scan_parser.add_argument("--bypass-min-delay", type=float, default=1.0, help="Minimum delay between requests")
    scan_parser.add_argument("--bypass-max-delay", type=float, default=3.0, help="Maximum delay between requests")
    scan_parser.add_argument("--proxy-file", help="File with proxy list for bypass")
    scan_parser.add_argument("--blacklist", help="File with blacklisted IPs/domains")
    scan_parser.add_argument("--skip-security-checks", action="store_true", help="Skip security validation checks")
    scan_parser.add_argument("--check-availability", action="store_true", help="Check target availability before scanning")
    
    # RESOLVE module
    resolve_parser = subparsers.add_parser('resolve', help='DNS to IP Resolution')
    resolve_parser.add_argument("-i", "--input", default="dns.txt", help="Input file with domains")
    resolve_parser.add_argument("-o", "--output", default="ip.txt", help="Output file for IPs")
    resolve_parser.add_argument("-t", "--workers", type=int, default=10, help="Number of workers")
    resolve_parser.add_argument("--ipv6", action="store_true", help="Include IPv6 addresses")
    
    # SUBDOMAIN module
    subdomain_parser = subparsers.add_parser('subdomain', help='Subdomain Enumeration')
    subdomain_subparsers = subdomain_parser.add_subparsers(dest='subdomain_mode', required=True)
    
    passive_parser = subdomain_subparsers.add_parser('passive', help='Passive collection from crt.sh')
    passive_parser.add_argument("-d", "--domain", required=True, help="Domain to enumerate")
    passive_parser.add_argument("-o", "--out", default="out", help="Output directory")
    passive_parser.add_argument("-t", "--threads", type=int, default=200, help="Concurrency")
    passive_parser.add_argument("--resolvers", help="File with DNS resolvers")
    passive_parser.add_argument("--http", action="store_true", help="HTTP inventory")
    
    brute_parser = subdomain_subparsers.add_parser('brute', help='Brute force with wordlist')
    brute_parser.add_argument("-d", "--domain", required=True, help="Domain to enumerate")
    brute_parser.add_argument("-w", "--wordlist", required=True, help="Wordlist file")
    brute_parser.add_argument("-o", "--out", default="out", help="Output directory")
    brute_parser.add_argument("-t", "--threads", type=int, default=200, help="Concurrency")
    brute_parser.add_argument("--resolvers", help="File with DNS resolvers")
    brute_parser.add_argument("--http", action="store_true", help="HTTP inventory")
    
    validate_parser = subdomain_subparsers.add_parser('validate', help='Validate existing list')
    validate_parser.add_argument("-i", "--input", required=True, help="Input file with subdomains")
    validate_parser.add_argument("-o", "--out", default="out", help="Output directory")
    validate_parser.add_argument("-t", "--threads", type=int, default=200, help="Concurrency")
    validate_parser.add_argument("--resolvers", help="File with DNS resolvers")
    validate_parser.add_argument("--http", action="store_true", help="HTTP inventory")
    
    # FUZZ module
    fuzz_parser = subparsers.add_parser('fuzz', help='Directory and VHost Fuzzing')
    fuzz_subparsers = fuzz_parser.add_subparsers(dest='fuzz_mode', required=True)
    
    dir_parser = fuzz_subparsers.add_parser('dir', help='Directory enumeration')
    dir_parser.add_argument("-u", required=True, help="Base URL")
    dir_parser.add_argument("-w", required=True, help="Wordlist file")
    dir_parser.add_argument("-t", type=int, default=50, help="Concurrency")
    dir_parser.add_argument("-S", nargs="*", type=int, default=[200, 204, 301, 302, 307, 401, 403], help="Status codes")
    dir_parser.add_argument("-e", default="", help="Extensions (comma-separated)")
    dir_parser.add_argument("--timeout", type=int, default=15, help="Timeout")
    dir_parser.add_argument("--ua", default="Valac/1.0", help="User-Agent")
    
    vhost_parser = fuzz_subparsers.add_parser('vhost', help='VHost enumeration')
    vhost_parser.add_argument("-u", required=True, help="Target URL")
    vhost_parser.add_argument("-b", required=True, help="Base IP")
    vhost_parser.add_argument("-w", required=True, help="Wordlist file")
    vhost_parser.add_argument("--domain", help="Domain")
    vhost_parser.add_argument("-t", type=int, default=50, help="Concurrency")
    vhost_parser.add_argument("-S", nargs="*", type=int, default=[200, 204, 301, 302, 307, 401, 403], help="Status codes")
    vhost_parser.add_argument("--timeout", type=int, default=15, help="Timeout")
    vhost_parser.add_argument("--ua", default="Valac/1.0", help="User-Agent")
    
    # EXTRACT module
    extract_parser = subparsers.add_parser('extract', help='Extract domains from CSV')
    extract_parser.add_argument("--input", required=True, help="Input CSV file")
    extract_parser.add_argument("--output", required=True, help="Output file for domains")
    extract_parser.add_argument("--columns", nargs="*", help="Columns to check (names or indices)")
    
    args = parser.parse_args()
    
    if not args.module:
        print_help()
        return
    
    # Clear screen and show banner
    os.system("clear" if os.name == "posix" else "cls")
    print(BANNER)
    
    try:
        # Route to appropriate module
        if args.module == 'scan':
            # Perform security checks if not skipped
            if not getattr(args, 'skip_security_checks', False):
                # Collect targets for validation
                targets_to_validate = []
                if args.ip:
                    targets_to_validate.append(args.ip)
                if args.domain:
                    targets_to_validate.append(args.domain)
                if args.file:
                    try:
                        with open(args.file, 'r', encoding='utf-8') as f:
                            targets_to_validate.extend([line.strip() for line in f if line.strip() and not line.startswith('#')])
                    except (FileNotFoundError, IOError, PermissionError, UnicodeDecodeError):
                        pass
                
                if targets_to_validate:
                    validator = perform_security_checks(
                        targets_to_validate,
                        check_network=True,
                        check_availability=getattr(args, 'check_availability', False)
                    )
                    validator.print_warnings()
                    if validator.errors:
                        validator.print_errors()
                        response = input(f"{YELLOW}Continue despite errors? (yes/no): {RESET}")
                        if response.lower() != 'yes':
                            print(f"{YELLOW}[INFO]{RESET} Scan cancelled by user")
                            return
            
            scanner = ScannerModule()
            # Set bypass flag
            args.use_bypass = getattr(args, 'bypass', False)
            
            # Apply blacklist if provided
            if hasattr(args, 'blacklist') and args.blacklist:
                blacklist_protection = BlacklistProtection(args.blacklist)
                # Filter targets will be done in scanner.run()
                scanner.blacklist_protection = blacklist_protection
            
            scanner.run(args)
            # Save bypass cache if used
            if scanner.use_bypass and scanner.bypass_system:
                scanner.bypass_system.save_cache()
                bypass_stats = scanner.bypass_system.get_stats()
                if bypass_stats['cached'] > 0:
                    print(f"{CYAN}[INFO]{RESET} Bypass stats: {bypass_stats['success']} success, {bypass_stats['cached']} cached, {bypass_stats['rate_limited']} rate limited")
        elif args.module == 'resolve':
            resolver = DNSResolverModule()
            resolver.run(args)
        elif args.module == 'subdomain':
            subenum = SubdomainEnumModule()
            subenum.run(args)
        elif args.module == 'fuzz':
            fuzzer = FuzzerModule()
            fuzzer.run(args)
        elif args.module == 'extract':
            extractor = CSVExtractorModule()
            extractor.run(args)
        else:
            print(f"{RED}[ERROR]{RESET} Unknown module: {args.module}")
            print_help()
            sys.exit(1)
            
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[WARN]{RESET} Operation interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n{RED}[ERROR]{RESET} Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()

