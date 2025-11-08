"""
DNS Resolver Module - Resolves domain names to IP addresses
"""

import socket
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Iterable, List, Set
from tqdm import tqdm

# Color codes
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
RESET = "\033[0m"


class DNSResolverModule:

    def resolve_domain_to_ips(self, domain: str, include_ipv6: bool = False, timeout: int = 5) -> Set[str]:
        """Resolve domain with timeout protection"""
        addresses: Set[str] = set()
        try:
            # Set socket timeout
            socket.setdefaulttimeout(timeout)
            for family, _, _, _, sockaddr in socket.getaddrinfo(domain, None):
                if family == socket.AF_INET:
                    ip = sockaddr[0]
                    addresses.add(ip)
                elif include_ipv6 and family == socket.AF_INET6:
                    ip6 = sockaddr[0]
                    addresses.add(ip6)
        except socket.timeout:
            pass  # Timeout is expected for unreachable domains
        except socket.gaierror:
            pass  # DNS error is expected for non-existent domains
        except Exception:
            pass  # Other errors are silently ignored
        finally:
            # Reset timeout to default
            socket.setdefaulttimeout(None)
        return addresses

    def write_ips_to_file(self, ips: Iterable[str], path: str) -> None:
        with open(path, "w", encoding="utf-8") as file:
            for ip in sorted(set(ips)):
                file.write(f"{ip}\n")

    def collect_ips_from_domains(self, domains: Iterable[str], workers: int = 10, include_ipv6: bool = False) -> Set[str]:
        all_ips: Set[str] = set()
        domains_list = list(domains)
        total = len(domains_list)
        
        pbar = tqdm(
            total=total,
            desc=f"{YELLOW}[RESOLVE]{RESET} Resolving domains",
            unit="domain",
            bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]',
            colour='cyan'
        )
        
        with ThreadPoolExecutor(max_workers=workers) as executor:
            future_to_domain = {
                executor.submit(self.resolve_domain_to_ips, domain, include_ipv6): domain
                for domain in domains_list
            }
            for future in as_completed(future_to_domain):
                try:
                    ips = future.result()
                    all_ips.update(ips)
                    domain = future_to_domain[future]
                    pbar.set_postfix({
                        'IPs': len(all_ips),
                        'Current': domain[:30] + '...' if len(domain) > 30 else domain
                    })
                except Exception:
                    pass
                finally:
                    pbar.update(1)
        
        pbar.close()
        return all_ips

    def read_domains_from_file(self, path: str) -> List[str]:
        """Read domains from file with error handling"""
        try:
            if not os.path.exists(path):
                print(f"{RED}[ERROR]{RESET} File not found: {path}")
                return []
            domains = []
            with open(path, "r", encoding="utf-8") as file:
                for line in file:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    # Extract domain part (before first space, in case file has "domain ip" format)
                    parts = line.split()
                    if not parts:
                        continue
                    domain = parts[0]
                    # Skip if it looks like an IP address (simple check - 4 numbers separated by dots)
                    if not self._is_ip_address(domain):
                        domains.append(domain)
            return domains
        except Exception as e:
            print(f"{RED}[ERROR]{RESET} Error reading file {path}: {e}")
            return []
    
    def _is_ip_address(self, value: str) -> bool:
        """Check if a string is an IP address (must be exactly 4 numbers 0-255 separated by dots)"""
        try:
            parts = value.split('.')
            if len(parts) != 4:
                return False
            # All parts must be numeric and in valid IP range
            return all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)
        except (ValueError, AttributeError):
            pass
        return False

    def run(self, args):
        if not os.path.exists(args.input):
            print(f"{RED}[ERROR]{RESET} Input file not found: {args.input}")
            print(f"{YELLOW}[INFO]{RESET} Please create {args.input} with domains (one per line) or specify a different file with -i/--input")
            return
        
        print(f"{YELLOW}[INFO]{RESET} Reading domains from {args.input}...")
        domains = self.read_domains_from_file(args.input)
        
        if not domains:
            print(f"{RED}[ERROR]{RESET} No domains found in {args.input}")
            print(f"{YELLOW}[INFO]{RESET} File should contain one domain per line")
            return
        
        print(f"{GREEN}[INFO]{RESET} Loaded {len(domains)} domains")
        
        print(f"{YELLOW}[INFO]{RESET} Resolving domains to IPs (workers: {args.workers})...")
        ips = self.collect_ips_from_domains(domains, workers=args.workers, include_ipv6=args.ipv6)
        
        print(f"{GREEN}[INFO]{RESET} Resolved {len(ips)} unique IP addresses")
        
        if ips:
            self.write_ips_to_file(ips, args.output)
            print(f"{GREEN}[SUCCESS]{RESET} IPs saved to {args.output}")
        else:
            print(f"{YELLOW}[WARN]{RESET} No IPs resolved from domains")

