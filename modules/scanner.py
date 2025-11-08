"""
Scanner Module - IP Vulnerability Scanner
Uses Shodan InternetDB API to scan IPs for vulnerabilities
"""

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import ipaddress
import csv
import threading
import datetime
import os
import time
import random
import json
import socket
import sqlite3
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import List, Dict, Optional, Any
from tqdm import tqdm
from collections import deque
from .bypass_system import BypassSystem
from .visualizer import DashboardGenerator

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

# Color codes
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
BLUE = "\033[94m"
CYAN = "\033[96m"
RESET = "\033[0m"


@dataclass
class ScanResult:
    ip: str
    ports: List[int]
    vulns: List[str]
    hostnames: List[str]
    cpe: List[str]
    tags: List[str]
    timestamp: str
    response_time: float
    geolocation: Dict[str, Any]
    technologies: List[str]
    severity_score: float
    risk_level: str


class Database:
    def __init__(self, db_path: str = "scans.db"):
        self.db_path = db_path
        self.init_db()

    def init_db(self):
        conn = sqlite3.connect(self.db_path)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_history
            (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                ports TEXT,
                vulns TEXT,
                hostnames TEXT,
                severity_score REAL,
                risk_level TEXT,
                response_time REAL,
                geolocation TEXT,
                technologies TEXT,
                tags TEXT,
                cpe TEXT
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_ip ON scan_history(ip)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON scan_history(timestamp)")
        conn.commit()
        conn.close()

    def save_result(self, result: ScanResult):
        conn = sqlite3.connect(self.db_path)
        conn.execute("""
            INSERT INTO scan_history
            (ip, timestamp, ports, vulns, hostnames, severity_score, risk_level,
             response_time, geolocation, technologies, tags, cpe)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            result.ip,
            result.timestamp,
            json.dumps(result.ports),
            json.dumps(result.vulns),
            json.dumps(result.hostnames),
            result.severity_score,
            result.risk_level,
            result.response_time,
            json.dumps(result.geolocation),
            json.dumps(result.technologies),
            json.dumps(result.tags),
            json.dumps(result.cpe)
        ))
        conn.commit()
        conn.close()


class ScannerModule:
    def __init__(self):
        self.max_workers = 10
        self.timeout = 5
        self.delay = 0.1
        self.cache = {}
        self.session = requests.Session()
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        ]
        self.session.headers.update({'User-Agent': random.choice(self.user_agents)})
        retries = Retry(total=3, backoff_factor=0.5, status_forcelist=[429, 500, 502, 503, 504])
        adapter = HTTPAdapter(max_retries=retries, pool_connections=50, pool_maxsize=50)
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)
        self.database = None
        self.enable_database = False
        self.enable_geolocation = False
        self.webhook_url = None
        self.requests_per_second = None
        self._rate_lock = threading.Lock()
        self._next_available_time = 0.0
        self.bypass_system = None
        self.use_bypass = False
        self.scan_results = []  # Store results for XML/HTML output
        self.results_lock = threading.Lock()
        self.blacklist_protection = None  # Blacklist protection instance
        self.stats = {
            'scanned': 0,
            'errors': 0,
            'vulns_found': 0,
            'critical_ips': [],
            'start_time': None,
            'end_time': None,
            'memory_samples': deque(maxlen=100),  # Track memory usage
            'last_memory_check': 0
        }

    def get_severity_color(self, cvss_score):
        if cvss_score is None:
            cvss_score = 0
        colors = [
            (9.0, f"{RED}[CRITICAL]{RESET}"),
            (7.0, f"{RED}[HIGH]{RESET}"),
            (4.0, f"{YELLOW}[MEDIUM]{RESET}"),
            (0.0, f"{GREEN}[LOW]{RESET}")
        ]
        return next(color for threshold, color in colors if cvss_score >= threshold)

    def calculate_severity_score(self, vulns: List[str], cve_cache: Dict) -> float:
        if not vulns:
            return 0.0
        scores = []
        for vuln in vulns:
            cve_info = cve_cache.get(vuln, {})
            # Try multiple CVSS score fields (different APIs use different field names)
            cvss = (cve_info.get('cvss_v3') or 
                   cve_info.get('cvss_v3_score') or
                   cve_info.get('cvss') or 
                   cve_info.get('cvss_score') or
                   cve_info.get('score') or 0)
            # Convert to float if it's a string
            try:
                cvss = float(cvss) if cvss else 0.0
            except (ValueError, TypeError):
                cvss = 0.0
            # Only add non-zero scores
            if cvss > 0:
                scores.append(cvss)
        # Return average of scores, or 0 if no valid scores found
        return sum(scores) / len(scores) if scores else 0.0

    def get_risk_level(self, severity_score: float) -> str:
        if severity_score >= 9.0:
            return "CRITICAL"
        elif severity_score >= 7.0:
            return "HIGH"
        elif severity_score >= 4.0:
            return "MEDIUM"
        else:
            return "LOW"

    def fetch_cve_details(self, cve_id):
        if cve_id in self.cache:
            entry = self.cache[cve_id]
            # Check if cache entry is expired (older than 24 hours)
            if '_ts' in entry:
                age = time.time() - entry['_ts']
                if age < 86400:  # 24 hours
                    return {k: v for k, v in entry.items() if k != '_ts'}
            else:
                return {k: v for k, v in entry.items() if k != '_ts'}

        try:
            url = f"https://cvedb.shodan.io/cve/{cve_id}"
            response = self.session.get(url, timeout=self.timeout)
            if response.status_code == 200:
                data = response.json()
                stored = dict(data)
                stored['_ts'] = time.time()
                self.cache[cve_id] = stored
                return data
        except requests.RequestException:
            pass
        # Return empty dict with default score if API fails
        return {}

    def fetch_geolocation(self, ip: str) -> Dict[str, Any]:
        if not self.enable_geolocation:
            return {}
        try:
            response = self.session.get(f"http://ip-api.com/json/{ip}", timeout=3)
            if response.status_code == 200:
                data = response.json()
                # Normalize field names for consistency
                return {
                    'lat': data.get('lat'),
                    'lon': data.get('lon'),
                    'city': data.get('city'),
                    'country': data.get('country'),
                    'regionName': data.get('regionName'),
                    'region': data.get('regionName'),
                    'isp': data.get('isp'),
                    'org': data.get('org'),
                    'as': data.get('as'),
                    'query': data.get('query')
                }
        except (requests.RequestException, KeyError, ValueError) as e:
            # Silently ignore geolocation errors
            pass
        return {}

    def detect_technologies(self, ports: List[int]) -> List[str]:
        tech_map = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
            53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
            443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
            5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt",
            27017: "MongoDB", 5900: "VNC", 1433: "MSSQL"
        }
        return [tech_map.get(port, f"Port-{port}") for port in ports if port in tech_map]

    def send_webhook_notification(self, result: ScanResult):
        if not self.webhook_url:
            return
        try:
            payload = {
                "ip": result.ip,
                "severity": result.severity_score,
                "risk_level": result.risk_level,
                "vulns_count": len(result.vulns),
                "vulns": result.vulns[:5],
                "timestamp": result.timestamp
            }
            requests.post(self.webhook_url, json=payload, timeout=5)
        except (requests.RequestException, ConnectionError, TimeoutError) as e:
            # Silently ignore webhook errors to not interrupt scanning
            pass

    def format_output(self, ip, data, options):
        results = []
        timestamp = f"{YELLOW}[INFO]{RESET}"
        base = f"{timestamp} {BLUE}[{ip}]{RESET}"
        show_all = not any(options.values())

        if options.get('ports') or show_all:
            if ports := data.get("ports"):
                ports_str = ', '.join(f"{GREEN}{port}{RESET}" for port in ports)
                results.append(f"{base} [PORTS: {ports_str}]")

        if options.get('cves') or show_all:
            for cve in data.get("vulns", []):
                cve_info = self.fetch_cve_details(cve)
                severity = self.get_severity_color(cve_info.get("cvss_v3", 0))
                desc = cve_info.get("summary", "No description")[:80]
                results.append(f"{base} [{GREEN}{cve}{RESET}] {severity} [{GREEN}{desc}{RESET}]")

        if options.get('host') or show_all:
            if hostnames := data.get("hostnames"):
                hosts_str = ', '.join(f"{GREEN}{host}{RESET}" for host in hostnames)
                results.append(f"{base} [HOSTNAMES: {hosts_str}]")

        return results

    def save_results(self, result: ScanResult, jsonl_file=None, csv_file=None):
        data_dict = {
            'ip': result.ip,
            'timestamp': result.timestamp,
            'ports': result.ports,
            'vulns': result.vulns,
            'hostnames': result.hostnames,
            'severity_score': result.severity_score,
            'risk_level': result.risk_level,
            'response_time': result.response_time,
            'geolocation': result.geolocation,
            'technologies': result.technologies
        }

        if jsonl_file:
            try:
                with open(jsonl_file, 'a', encoding='utf-8') as f:
                    json.dump(data_dict, f)
                    f.write('\n')
            except Exception as e:
                print(f"{RED}[ERROR]{RESET} Failed to write JSONL: {e}")

        if csv_file:
            try:
                header = ['ip', 'timestamp', 'ports', 'vulns', 'hostnames', 'severity_score', 'risk_level', 'response_time']
                file_exists = os.path.exists(csv_file)
                with open(csv_file, 'a', newline='', encoding='utf-8') as f:
                    writer = csv.DictWriter(f, fieldnames=header)
                    if not file_exists or os.path.getsize(csv_file) == 0:
                        writer.writeheader()
                    writer.writerow({
                        'ip': result.ip,
                        'timestamp': result.timestamp,
                        'ports': ','.join(map(str, result.ports)),
                        'vulns': ','.join(result.vulns),
                        'hostnames': ','.join(result.hostnames),
                        'severity_score': result.severity_score,
                        'risk_level': result.risk_level,
                        'response_time': result.response_time
                    })
            except Exception as e:
                print(f"{RED}[ERROR]{RESET} Failed to write CSV: {e}")

        if self.enable_database and self.database:
            self.database.save_result(result)
    
    def save_to_xml(self, results: List[ScanResult], filename: str):
        """Save results to XML file"""
        try:
            import xml.etree.ElementTree as ET
            root = ET.Element("valac_scan")
            root.set("timestamp", datetime.datetime.now().isoformat())
            
            for result in results:
                scan = ET.SubElement(root, "target")
                ET.SubElement(scan, "ip").text = result.ip
                ET.SubElement(scan, "severity").text = str(result.severity_score)
                ET.SubElement(scan, "risk_level").text = result.risk_level
                ET.SubElement(scan, "response_time").text = str(result.response_time)
                
                ports_elem = ET.SubElement(scan, "ports")
                for port in result.ports:
                    ET.SubElement(ports_elem, "port").text = str(port)
                
                vulns_elem = ET.SubElement(scan, "vulnerabilities")
                for vuln in result.vulns:
                    ET.SubElement(vulns_elem, "cve").text = vuln
                
                hosts_elem = ET.SubElement(scan, "hostnames")
                for host in result.hostnames:
                    ET.SubElement(hosts_elem, "hostname").text = host
            
            tree = ET.ElementTree(root)
            tree.write(filename, encoding='utf-8', xml_declaration=True)
            print(f"{GREEN}[INFO]{RESET} XML report saved to {filename}")
        except Exception as e:
            print(f"{RED}[ERROR]{RESET} Failed to save XML: {e}")
    
    def save_to_html(self, results: List[ScanResult], filename: str, interactive: bool = True):
        """Save results to HTML file (interactive dashboard or simple report)"""
        try:
            if interactive:
                # Use interactive dashboard
                self.save_to_dashboard(results, filename)
            else:
                # Use simple HTML report
                html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Valac Scan Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        h1 {{ color: #333; text-align: center; }}
        .summary {{ background: white; padding: 20px; margin: 20px 0; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        table {{ width: 100%; border-collapse: collapse; background: white; margin: 20px 0; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #667eea; color: white; }}
        .critical {{ background: #ffebee; }}
        .high {{ background: #fff3e0; }}
        .medium {{ background: #fffbf0; }}
        .low {{ background: #f0fff4; }}
    </style>
</head>
<body>
    <h1>🔍 Valac Security Scan Report</h1>
    <div class="summary">
        <h2>Summary</h2>
        <p>Scan Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p>Total Targets: {len(results)}</p>
        <p>Total Vulnerabilities: {sum(len(r.vulns) for r in results)}</p>
        <p>Critical/High Risk: {sum(1 for r in results if r.severity_score >= 7.0)}</p>
    </div>
    <table>
        <tr>
            <th>IP Address</th>
            <th>Ports</th>
            <th>Vulnerabilities</th>
            <th>Severity</th>
            <th>Risk Level</th>
        </tr>
"""
                for result in sorted(results, key=lambda x: x.severity_score, reverse=True):
                    severity_class = result.risk_level.lower()
                    html += f"""        <tr class="{severity_class}">
            <td>{result.ip}</td>
            <td>{', '.join(map(str, result.ports[:10]))}</td>
            <td>{', '.join(result.vulns[:5])}</td>
            <td>{result.severity_score:.1f}</td>
            <td><strong>{result.risk_level}</strong></td>
        </tr>
"""
                html += """    </table>
</body>
</html>"""
                
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(html)
                print(f"{GREEN}[INFO]{RESET} HTML report saved to {filename}")
        except Exception as e:
            print(f"{RED}[ERROR]{RESET} Failed to save HTML: {e}")
    
    def save_to_dashboard(self, results: List[ScanResult], filename: str):
        """Save results to interactive dashboard"""
        try:
            # Convert ScanResult to dict format for visualizer
            results_dict = []
            for result in results:
                result_dict = {
                    'ip': result.ip,
                    'ports': result.ports,
                    'vulns': result.vulns,
                    'hostnames': result.hostnames,
                    'severity_score': result.severity_score,
                    'risk_level': result.risk_level,
                    'geolocation': {}
                }
                
                # Process geolocation if available
                if result.geolocation:
                    geo = result.geolocation
                    result_dict['geolocation'] = {
                        'lat': geo.get('lat'),
                        'lon': geo.get('lon'),
                        'city': geo.get('city'),
                        'country': geo.get('country'),
                        'region': geo.get('regionName'),
                        'isp': geo.get('isp')
                    }
                
                results_dict.append(result_dict)
            
            # Generate dashboard
            generator = DashboardGenerator()
            generator.generate(results_dict, filename)
            print(f"{GREEN}[INFO]{RESET} Interactive dashboard saved to {filename}")
        except Exception as e:
            print(f"{RED}[ERROR]{RESET} Failed to save dashboard: {e}")
            import traceback
            traceback.print_exc()

    def process_ip(self, ip, options, jsonl_file=None, csv_file=None):
        """Process single IP with timeout and exception protection"""
        start_time = time.time()
        max_ip_timeout = 60  # Maximum time per IP
        
        try:
            # Use bypass system if enabled
            if self.use_bypass and self.bypass_system:
                result = self.bypass_system.fetch_with_bypass(ip)
                if result and result.get('data'):
                    data = result['data']
                    response_time = time.time() - start_time
                else:
                    self.stats['scanned'] += 1
                    return
            else:
                # Standard method
                url = f"https://internetdb.shodan.io/{ip}"

                if self.requests_per_second:
                    with self._rate_lock:
                        now = time.time()
                        wait = max(0.0, self._next_available_time - now)
                        self._next_available_time = max(self._next_available_time, now) + (1.0 / self.requests_per_second)
                    if wait > 0:
                        time.sleep(wait)

                response = self.session.get(url, timeout=self.timeout)
                response_time = time.time() - start_time
                
                if response.status_code != 200:
                    if response.status_code == 404:
                        tqdm.write(f"{YELLOW}[WARN]{RESET} No data found for {ip}")
                    else:
                        self.stats['errors'] += 1
                        tqdm.write(f"{RED}[ERROR]{RESET} HTTP {response.status_code} for {ip}")
                    return
                
                data = response.json()

            ports = data.get("ports", [])
            vulns = data.get("vulns", [])
            hostnames = data.get("hostnames", [])
            cpe = data.get("cpe", [])
            tags = data.get("tags", [])

            # Fetch CVE details to populate cache before calculating severity score
            # This ensures CVSS scores are available for severity calculation
            for vuln in vulns:
                cve_info = self.fetch_cve_details(vuln)
                # If CVE details not in cache yet, try to get basic info
                if not cve_info and vuln not in self.cache:
                    # Store placeholder to avoid repeated API calls
                    self.cache[vuln] = {'_ts': time.time()}

            severity_score = self.calculate_severity_score(vulns, self.cache)
            risk_level = self.get_risk_level(severity_score)
            
            # If severity score is 0 but we have vulns, assign a default score based on count
            if severity_score == 0.0 and vulns:
                # Assign default score: 1 vuln = 3.0 (MEDIUM), 5+ vulns = 7.0 (HIGH), 10+ = 9.0 (CRITICAL)
                if len(vulns) >= 10:
                    severity_score = 9.0
                elif len(vulns) >= 5:
                    severity_score = 7.0
                elif len(vulns) >= 1:
                    severity_score = 4.0
                risk_level = self.get_risk_level(severity_score)
            geolocation = self.fetch_geolocation(ip) if self.enable_geolocation else {}
            technologies = self.detect_technologies(ports)

            result = ScanResult(
                ip=ip,
                ports=ports,
                vulns=vulns,
                hostnames=hostnames,
                cpe=cpe,
                tags=tags,
                timestamp=datetime.datetime.now().isoformat(),
                response_time=response_time,
                geolocation=geolocation,
                technologies=technologies,
                severity_score=severity_score,
                risk_level=risk_level
            )

            results = self.format_output(ip, data, options)
            for r in results:
                # Use tqdm.write() to ensure output is visible even with progress bar
                tqdm.write(r)

            self.save_results(result, jsonl_file, csv_file)
            
            # Store result for XML/HTML output
            with self.results_lock:
                self.scan_results.append(result)

            self.stats['scanned'] += 1
            self.stats['vulns_found'] += len(vulns)
            if severity_score >= 7.0:
                self.stats['critical_ips'].append(ip)
            
            # Periodic memory check (every 100 scans)
            if self.stats['scanned'] % 100 == 0:
                memory = self.check_memory()
                if memory and memory > 2048:  # Warn if > 2GB
                    tqdm.write(f"{YELLOW}[WARN]{RESET} High memory usage: {memory:.1f}MB")

            if risk_level in ["CRITICAL", "HIGH"]:
                self.send_webhook_notification(result)

            if self.delay and not self.use_bypass:
                time.sleep(self.delay)
            
            # Check for timeout
            elapsed = time.time() - start_time
            if elapsed > max_ip_timeout:
                self.stats['errors'] += 1
                tqdm.write(f"{YELLOW}[WARN]{RESET} IP {ip} processing exceeded timeout ({max_ip_timeout}s)")
                return

        except requests.Timeout:
            self.stats['errors'] += 1
            tqdm.write(f"{YELLOW}[WARN]{RESET} Request timeout for {ip}")
        except requests.RequestException as e:
            self.stats['errors'] += 1
            # Don't print full error for common network issues
            error_msg = str(e)
            if "Connection" in error_msg or "timeout" in error_msg.lower():
                tqdm.write(f"{YELLOW}[WARN]{RESET} Connection issue for {ip}")
            else:
                tqdm.write(f"{RED}[ERROR]{RESET} Request failed for {ip}: {error_msg[:100]}")
        except KeyboardInterrupt:
            raise  # Re-raise to allow proper cleanup
        except Exception as e:
            self.stats['errors'] += 1
            # Limit error message length
            error_msg = str(e)[:200]
            tqdm.write(f"{RED}[ERROR]{RESET} Unexpected error for {ip}: {error_msg}")

    def process_ips_concurrent(self, ips, options, jsonl_file=None, csv_file=None):
        # Clear output files if they exist (for fresh start)
        if jsonl_file and os.path.exists(jsonl_file):
            try:
                os.remove(jsonl_file)
            except (OSError, PermissionError) as e:
                # Silently ignore file deletion errors
                pass
        if csv_file and os.path.exists(csv_file):
            try:
                os.remove(csv_file)
            except (OSError, PermissionError) as e:
                # Silently ignore file deletion errors
                pass
        
        # Filter valid IPs
        valid_ips = [ip.strip() for ip in ips if ip.strip()]
        total_ips = len(valid_ips)
        
        if total_ips == 0:
            print(f"{YELLOW}[WARN]{RESET} No valid IPs to scan")
            return
        
        # Initialize progress bar
        operation = "Scanning IPs" if not self.use_bypass else "Scanning IPs (Bypass Mode)"
        pbar = tqdm(
            total=total_ips,
            desc=f"{CYAN}[SCAN]{RESET} {operation}",
            unit="IP",
            bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]',
            colour='green'
        )
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self.process_ip, ip, options, jsonl_file, csv_file): ip 
                      for ip in valid_ips}

            for future in as_completed(futures):
                try:
                    future.result()
                    pbar.update(1)
                    # Update description with current stats
                    pbar.set_postfix({
                        'Scanned': self.stats['scanned'],
                        'Errors': self.stats['errors'],
                        'Vulns': self.stats['vulns_found']
                    })
                except Exception as e:
                    ip = futures[future]
                    self.stats['errors'] += 1
                    pbar.write(f"{RED}[ERROR]{RESET} Failed processing {ip}: {str(e)}")
                    pbar.update(1)
        
        pbar.close()

    def validate_ip(self, ip):
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def read_ips_from_file(self, filename):
        try:
            with open(filename, 'r') as f:
                lines = [line.strip() for line in f if line.strip() and not line.startswith('#')]

            ips = []
            for line in lines:
                if '/' in line:
                    try:
                        network = ipaddress.ip_network(line, strict=False)
                        ips.extend([str(ip) for ip in network.hosts()])
                    except ValueError:
                        pass
                elif self.validate_ip(line):
                    ips.append(line)

            return list(set(ips))
        except FileNotFoundError:
            print(f"{RED}[ERROR]{RESET} File not found: {filename}")
            return []
        except Exception as e:
            print(f"{RED}[ERROR]{RESET} Error reading file: {str(e)}")
            return []

    def resolve_domain_to_ips(self, domain: str) -> List[str]:
        try:
            ips = socket.gethostbyname_ex(domain)[2]
            return ips
        except (socket.gaierror, socket.herror, OSError):
            return []

    def check_memory(self):
        """Check and record memory usage"""
        if not PSUTIL_AVAILABLE:
            return
        try:
            process = psutil.Process(os.getpid())
            memory_mb = process.memory_info().rss / 1024 / 1024
            self.stats['memory_samples'].append(memory_mb)
            self.stats['last_memory_check'] = time.time()
            return memory_mb
        except (OSError, AttributeError):
            # Silently ignore memory check errors
            return 0

    def print_statistics(self):
        if not self.stats['start_time']:
            return

        duration = (self.stats['end_time'] or time.time()) - self.stats['start_time']
        
        # Get memory stats
        memory_info = ""
        if PSUTIL_AVAILABLE and self.stats['memory_samples']:
            avg_memory = sum(self.stats['memory_samples']) / len(self.stats['memory_samples'])
            max_memory = max(self.stats['memory_samples'])
            memory_info = f"\n{YELLOW}Memory usage:{RESET} Avg: {avg_memory:.1f}MB, Peak: {max_memory:.1f}MB"

        print(f"\n{CYAN}{'=' * 60}{RESET}")
        print(f"{CYAN}                   SCAN STATISTICS{RESET}")
        print(f"{CYAN}{'=' * 60}{RESET}")
        print(f"{YELLOW}Targets scanned:{RESET} {self.stats['scanned']}")
        print(f"{YELLOW}Errors:{RESET} {self.stats['errors']}")
        print(f"{YELLOW}Vulnerabilities found:{RESET} {self.stats['vulns_found']}")
        print(f"{RED}Critical/High risk IPs:{RESET} {len(self.stats['critical_ips'])}")
        print(f"{YELLOW}Scan duration:{RESET} {duration:.2f}s")
        if duration > 0:
            print(f"{YELLOW}Scan rate:{RESET} {self.stats['scanned'] / duration:.2f} targets/s")
        if memory_info:
            print(memory_info)

        if self.stats['critical_ips']:
            print(f"\n{RED}Top Critical IPs:{RESET}")
            for ip in self.stats['critical_ips'][:10]:
                print(f"  • {ip}")

        print(f"{CYAN}{'=' * 60}{RESET}\n")

    def run(self, args):
        self.max_workers = args.threads
        self.timeout = args.timeout
        self.delay = args.delay
        self.requests_per_second = args.rps
        self.enable_geolocation = args.geolocation
        self.webhook_url = args.webhook

        if args.database:
            self.enable_database = True
            self.database = Database(args.database)

        if hasattr(args, 'user_agent') and args.user_agent:
            self.session.headers.update({'User-Agent': args.user_agent})
        
        # Initialize bypass system if enabled
        if hasattr(args, 'use_bypass') and args.use_bypass:
            bypass_config = {
                'num_sessions': getattr(args, 'bypass_sessions', 10),
                'requests_per_minute': getattr(args, 'bypass_rpm', 30),
                'cache_file': getattr(args, 'bypass_cache', 'shodan_cache.json'),
                'cache_hours': getattr(args, 'bypass_cache_hours', 24),
                'min_delay': getattr(args, 'bypass_min_delay', 1.0),
                'max_delay': getattr(args, 'bypass_max_delay', 3.0),
                'timeout': self.timeout,
                'proxy_file': getattr(args, 'proxy_file', None),
                'use_proxy': hasattr(args, 'proxy_file') and args.proxy_file
            }
            self.bypass_system = BypassSystem(bypass_config)
            self.use_bypass = True
            print(f"{GREEN}[INFO]{RESET} Bypass system enabled (RPM: {bypass_config['requests_per_minute']}, Sessions: {bypass_config['num_sessions']})")

        options = {
            'cves': args.cves,
            'ports': args.ports,
            'host': args.host,
            'cve_ports': False
        }

        targets = []

        if args.ip:
            if self.validate_ip(args.ip):
                targets.append(args.ip)
            else:
                print(f"{RED}[ERROR]{RESET} Invalid IP format: {args.ip}")
                return

        if args.domain:
            print(f"{YELLOW}[INFO]{RESET} Resolving domain: {args.domain}")
            resolved_ips = self.resolve_domain_to_ips(args.domain)
            if resolved_ips:
                print(f"{GREEN}[INFO]{RESET} Resolved {len(resolved_ips)} IP(s)")
                targets.extend(resolved_ips)
            else:
                print(f"{RED}[ERROR]{RESET} Could not resolve domain: {args.domain}")

        if args.cidr:
            try:
                network = ipaddress.ip_network(args.cidr, strict=False)
                cidr_ips = [str(ip) for ip in network.hosts()]
                print(f"{YELLOW}[INFO]{RESET} CIDR {args.cidr} expanded to {len(cidr_ips)} hosts")
                targets.extend(cidr_ips)
            except ValueError:
                print(f"{RED}[ERROR]{RESET} Invalid CIDR: {args.cidr}")
                return

        if args.dns_file:
            try:
                with open(args.dns_file, 'r') as f:
                    domains = [line.strip() for line in f if line.strip() and not line.startswith('#')]

                print(f"{YELLOW}[INFO]{RESET} Resolving {len(domains)} domains...")
                for domain in domains:
                    resolved = self.resolve_domain_to_ips(domain)
                    if resolved:
                        targets.extend(resolved)
                print(f"{GREEN}[INFO]{RESET} Resolved {len(targets)} total IPs from domains")
            except FileNotFoundError:
                print(f"{RED}[ERROR]{RESET} DNS file not found: {args.dns_file}")
                return

        if args.file:
            ips = self.read_ips_from_file(args.file)
            if ips:
                print(f"{YELLOW}[INFO]{RESET} Loaded {len(ips)} targets from file")
                
                # Apply blacklist if available
                if self.blacklist_protection:
                    valid_ips, blacklisted_ips = self.blacklist_protection.filter_blacklisted(ips)
                    if blacklisted_ips:
                        print(f"{YELLOW}[WARN]{RESET} {len(blacklisted_ips)} targets filtered by blacklist")
                        for bl_item in blacklisted_ips[:5]:  # Show first 5
                            print(f"  {YELLOW}-{RESET} {bl_item}")
                        if len(blacklisted_ips) > 5:
                            print(f"  {YELLOW}... and {len(blacklisted_ips) - 5} more{RESET}")
                    ips = valid_ips
                
                targets.extend(ips)
            else:
                print(f"{RED}[ERROR]{RESET} No valid IPs found in file")
                return

        if not targets:
            print(f"{YELLOW}[INFO]{RESET} No targets specified, running demo scan on localhost")
            targets = ["127.0.0.1"]

        targets = sorted(set(targets))

        print(f"\n{CYAN}{'=' * 60}{RESET}")
        print(f"{CYAN}Starting Scan{RESET}")
        print(f"{CYAN}{'=' * 60}{RESET}")
        print(f"{YELLOW}Total targets:{RESET} {len(targets)}")
        print(f"{YELLOW}Threads:{RESET} {self.max_workers}")
        print(f"{YELLOW}Timeout:{RESET} {self.timeout}s")
        print(f"{CYAN}{'=' * 60}{RESET}\n")

        self.stats['start_time'] = time.time()
        # Clear previous results
        with self.results_lock:
            self.scan_results = []

        try:
            self.process_ips_concurrent(targets, options, args.jsonl, args.csv_file)
        except KeyboardInterrupt:
            print(f"\n{YELLOW}[WARN]{RESET} Scan interrupted by user")
        finally:
            self.stats['end_time'] = time.time()

        if args.show_stats or len(targets) > 1:
            self.print_statistics()
        
        # Save XML/HTML reports if requested
        if hasattr(args, 'xml_file') and args.xml_file:
            with self.results_lock:
                self.save_to_xml(self.scan_results, args.xml_file)
        
        if hasattr(args, 'html_file') and args.html_file:
            with self.results_lock:
                self.save_to_html(self.scan_results, args.html_file, interactive=True)
        
        if hasattr(args, 'html_simple') and args.html_simple:
            with self.results_lock:
                self.save_to_html(self.scan_results, args.html_simple, interactive=False)

        print(f"\n{GREEN}[SUCCESS]{RESET} Scan completed!")

        if self.stats['critical_ips']:
            print(f"\n{RED}⚠ WARNING: Found {len(self.stats['critical_ips'])} critical/high risk targets!{RESET}")

