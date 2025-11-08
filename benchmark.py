#!/usr/bin/env python3
"""
Benchmark script for Valac performance testing
Tests scanner performance on large IP ranges (100k+ IPs)
"""

import time
import json
import statistics
import argparse
import ipaddress
import sys
from pathlib import Path
from typing import List, Dict

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from modules.scanner import ScannerModule
from modules.bypass_system import BypassSystem

# Color codes
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
BLUE = "\033[94m"
CYAN = "\033[96m"
RESET = "\033[0m"


class BenchmarkRunner:
    def __init__(self):
        self.results = []
        
    def generate_test_ips(self, count: int, start_ip: str = "192.168.1.1") -> List[str]:
        """Generate test IP addresses"""
        base = ipaddress.IPv4Address(start_ip)
        ips = []
        for i in range(count):
            try:
                ip = str(ipaddress.IPv4Address(int(base) + i))
                ips.append(ip)
            except:
                break
        return ips
    
    def benchmark_scan(self, ips: List[str], config: Dict, test_name: str) -> Dict:
        """Run benchmark scan with given configuration"""
        print(f"\n{CYAN}{'='*70}{RESET}")
        print(f"{CYAN}Benchmark: {test_name}{RESET}")
        print(f"{CYAN}{'='*70}{RESET}")
        print(f"{YELLOW}Configuration:{RESET}")
        for key, value in config.items():
            print(f"  {key}: {value}")
        print(f"{YELLOW}IPs to scan:{RESET} {len(ips)}")
        
        # Create mock args object
        class Args:
            def __init__(self, config_dict):
                for key, value in config_dict.items():
                    setattr(self, key, value)
                self.cves = False
                self.ports = False
                self.host = False
                self.jsonl = None
                self.csv_file = None
                self.xml_file = None
                self.html_file = None
                self.database = None
                self.geolocation = False
                self.webhook = None
                self.show_stats = False
                self.use_bypass = config_dict.get('bypass', False)
                self.bypass = config_dict.get('bypass', False)
        
        args = Args(config)
        
        scanner = ScannerModule()
        scanner.max_workers = config.get('threads', 10)
        scanner.timeout = config.get('timeout', 5)
        scanner.delay = config.get('delay', 0.1)
        
        # Initialize bypass if enabled
        if config.get('bypass', False):
            bypass_config = {
                'num_sessions': config.get('bypass_sessions', 10),
                'requests_per_minute': config.get('bypass_rpm', 30),
                'cache_file': 'benchmark_cache.json',
                'cache_hours': 24,
                'min_delay': config.get('bypass_min_delay', 1.0),
                'max_delay': config.get('bypass_max_delay', 3.0),
                'timeout': config.get('timeout', 5),
                'proxy_file': None,
                'use_proxy': False
            }
            scanner.bypass_system = BypassSystem(bypass_config)
            scanner.use_bypass = True
        
        # Run benchmark
        start_time = time.time()
        scanner.run(args)
        end_time = time.time()
        
        duration = end_time - start_time
        rate = len(ips) / duration if duration > 0 else 0
        
        result = {
            'test_name': test_name,
            'config': config,
            'ips_count': len(ips),
            'duration': duration,
            'rate': rate,
            'scanned': scanner.stats.get('scanned', 0),
            'errors': scanner.stats.get('errors', 0),
            'vulns_found': scanner.stats.get('vulns_found', 0),
            'success_rate': (scanner.stats.get('scanned', 0) / len(ips) * 100) if len(ips) > 0 else 0
        }
        
        if scanner.use_bypass and scanner.bypass_system:
            bypass_stats = scanner.bypass_system.get_stats()
            result['bypass_stats'] = bypass_stats
        
        print(f"\n{GREEN}Results:{RESET}")
        print(f"  Duration: {duration:.2f}s")
        print(f"  Rate: {rate:.2f} IPs/s")
        print(f"  Scanned: {result['scanned']}")
        print(f"  Errors: {result['errors']}")
        print(f"  Success rate: {result['success_rate']:.2f}%")
        
        if scanner.use_bypass and scanner.bypass_system:
            print(f"  Bypass cached: {bypass_stats.get('cached', 0)}")
            print(f"  Bypass rate limited: {bypass_stats.get('rate_limited', 0)}")
        
        return result
    
    def run_benchmark_suite(self, ip_count: int = 1000):
        """Run comprehensive benchmark suite"""
        print(f"{GREEN}{'='*70}{RESET}")
        print(f"{GREEN}Valac Performance Benchmark Suite{RESET}")
        print(f"{GREEN}{'='*70}{RESET}")
        print(f"{YELLOW}Generating {ip_count} test IPs...{RESET}")
        
        test_ips = self.generate_test_ips(ip_count)
        print(f"{GREEN}Generated {len(test_ips)} test IPs{RESET}")
        
        # Test configurations
        configs = [
            {
                'name': 'Standard Scan (10 threads)',
                'threads': 10,
                'timeout': 5,
                'delay': 0.1,
                'bypass': False
            },
            {
                'name': 'Standard Scan (20 threads)',
                'threads': 20,
                'timeout': 5,
                'delay': 0.1,
                'bypass': False
            },
            {
                'name': 'Bypass System (30 RPM, 10 sessions)',
                'threads': 10,
                'timeout': 5,
                'delay': 0.1,
                'bypass': True,
                'bypass_rpm': 30,
                'bypass_sessions': 10,
                'bypass_min_delay': 1.0,
                'bypass_max_delay': 3.0
            },
            {
                'name': 'Bypass System (20 RPM, 15 sessions)',
                'threads': 10,
                'timeout': 5,
                'delay': 0.1,
                'bypass': True,
                'bypass_rpm': 20,
                'bypass_sessions': 15,
                'bypass_min_delay': 2.0,
                'bypass_max_delay': 5.0
            },
        ]
        
        results = []
        for config in configs:
            try:
                result = self.benchmark_scan(test_ips, config, config['name'])
                results.append(result)
                time.sleep(2)  # Brief pause between tests
            except Exception as e:
                print(f"{RED}Error in benchmark: {e}{RESET}")
                continue
        
        # Summary
        self.print_summary(results)
        
        # Save results
        output_file = f"benchmark_results_{int(time.time())}.json"
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\n{GREEN}Results saved to: {output_file}{RESET}")
        
        return results
    
    def print_summary(self, results: List[Dict]):
        """Print benchmark summary"""
        print(f"\n{CYAN}{'='*70}{RESET}")
        print(f"{CYAN}Benchmark Summary{RESET}")
        print(f"{CYAN}{'='*70}{RESET}")
        
        print(f"\n{YELLOW}{'Test Name':<40} {'Duration':<12} {'Rate (IP/s)':<12} {'Success %':<10}{RESET}")
        print("-" * 70)
        
        for result in results:
            print(f"{result['test_name']:<40} {result['duration']:>10.2f}s {result['rate']:>10.2f} {result['success_rate']:>8.2f}%")
        
        # Find best configuration
        if results:
            best_rate = max(results, key=lambda x: x['rate'])
            best_success = max(results, key=lambda x: x['success_rate'])
            
            print(f"\n{GREEN}Best Performance:{RESET}")
            print(f"  Highest rate: {best_rate['test_name']} ({best_rate['rate']:.2f} IPs/s)")
            print(f"  Best success rate: {best_success['test_name']} ({best_success['success_rate']:.2f}%)")


def main():
    parser = argparse.ArgumentParser(description="Valac Performance Benchmark")
    parser.add_argument("-n", "--count", type=int, default=1000, help="Number of IPs to test (default: 1000)")
    parser.add_argument("--large", action="store_true", help="Run large-scale test (100k+ IPs)")
    
    args = parser.parse_args()
    
    if args.large:
        ip_count = 100000
        print(f"{YELLOW}WARNING: Large-scale test with {ip_count} IPs will take significant time{RESET}")
        response = input("Continue? (yes/no): ")
        if response.lower() != 'yes':
            print("Cancelled")
            return
    else:
        ip_count = args.count
    
    runner = BenchmarkRunner()
    runner.run_benchmark_suite(ip_count)


if __name__ == "__main__":
    main()

