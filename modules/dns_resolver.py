"""
DNS Resolver Module - Resolves domain names to IP addresses
"""

import socket
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Iterable, List, Set

# Color codes
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
RESET = "\033[0m"


class DNSResolverModule:

    def resolve_domain_to_ips(self, domain: str, include_ipv6: bool = False) -> Set[str]:
        addresses: Set[str] = set()
        try:
            for family, _, _, _, sockaddr in socket.getaddrinfo(domain, None):
                if family == socket.AF_INET:
                    ip = sockaddr[0]
                    addresses.add(ip)
                elif include_ipv6 and family == socket.AF_INET6:
                    ip6 = sockaddr[0]
                    addresses.add(ip6)
        except socket.gaierror:
            pass
        return addresses

    def write_ips_to_file(self, ips: Iterable[str], path: str) -> None:
        with open(path, "w", encoding="utf-8") as file:
            for ip in sorted(set(ips)):
                file.write(f"{ip}\n")

    def collect_ips_from_domains(self, domains: Iterable[str], workers: int = 10, include_ipv6: bool = False) -> Set[str]:
        all_ips: Set[str] = set()
        with ThreadPoolExecutor(max_workers=workers) as executor:
            future_to_domain = {
                executor.submit(self.resolve_domain_to_ips, domain, include_ipv6): domain
                for domain in domains
            }
            for future in as_completed(future_to_domain):
                try:
                    all_ips.update(future.result())
                except Exception:
                    pass
        return all_ips

    def read_domains_from_file(self, path: str) -> List[str]:
        """Read domains from file with error handling"""
        try:
            if not os.path.exists(path):
                print(f"{RED}[ERROR]{RESET} File not found: {path}")
                return []
            with open(path, "r", encoding="utf-8") as file:
                lines = [line.strip() for line in file]
            return [line for line in lines if line and not line.startswith("#")]
        except Exception as e:
            print(f"{RED}[ERROR]{RESET} Error reading file {path}: {e}")
            return []

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

