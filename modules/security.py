"""
Security Module - Self-protection and safety checks
Provides validation, exception handling, and security warnings
"""

import os
import sys
import socket
import ipaddress
import re
import time
from typing import List, Set, Optional, Tuple
from pathlib import Path

# Color codes
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[96m"
RESET = "\033[0m"

# Blacklisted IP ranges (private, localhost, multicast, etc.)
BLACKLISTED_RANGES = [
    ipaddress.ip_network('127.0.0.0/8'),      # Localhost
    ipaddress.ip_network('10.0.0.0/8'),       # Private
    ipaddress.ip_network('172.16.0.0/12'),    # Private
    ipaddress.ip_network('192.168.0.0/16'),   # Private
    ipaddress.ip_network('169.254.0.0/16'),   # Link-local
    ipaddress.ip_network('224.0.0.0/4'),      # Multicast
    ipaddress.ip_network('240.0.0.0/4'),      # Reserved
]


class SecurityValidator:
    """Validate targets and check security concerns"""
    
    def __init__(self):
        self.warnings = []
        self.errors = []
        self.blocked_ips = set()
    
    def check_permissions(self) -> Tuple[bool, Optional[str]]:
        """Check if running with appropriate permissions"""
        if sys.platform == 'win32':
            # On Windows, check if running as administrator
            try:
                import ctypes
                is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
                if not is_admin:
                    return False, "Not running as administrator. Some operations may require elevated privileges."
            except (OSError, AttributeError):
                # Silently ignore privilege check errors on Windows
                pass
        else:
            # On Unix, check if running as root
            if os.geteuid() == 0:
                return True, "Running as root - be careful with network operations"
        return True, None
    
    def validate_ip(self, ip: str) -> Tuple[bool, Optional[str]]:
        """Validate IP address and check if it's safe to scan"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            # Check if IP is in blacklisted ranges
            for blacklist_range in BLACKLISTED_RANGES:
                if ip_obj in blacklist_range:
                    return False, f"IP {ip} is in blacklisted range ({blacklist_range})"
            
            # Check if it's a loopback (unless explicitly allowed)
            if ip_obj.is_loopback:
                return False, f"IP {ip} is a loopback address"
            
            # Check if it's a link-local
            if ip_obj.is_link_local:
                return False, f"IP {ip} is a link-local address"
            
            return True, None
        except ValueError:
            return False, f"Invalid IP address format: {ip}"
    
    def validate_domain(self, domain: str) -> Tuple[bool, Optional[str]]:
        """Validate domain name format"""
        if not domain or len(domain) > 253:
            return False, "Domain name too long or empty"
        
        # Basic domain validation
        domain_pattern = re.compile(
            r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        )
        
        if not domain_pattern.match(domain):
            return False, f"Invalid domain format: {domain}"
        
        # Check for suspicious patterns
        suspicious_patterns = [
            r'localhost',
            r'127\.0\.0\.1',
            r'0\.0\.0\.0',
            r'\.local$',
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, domain, re.IGNORECASE):
                return False, f"Domain {domain} matches suspicious pattern"
        
        return True, None
    
    def check_target_availability(self, target: str, target_type: str = 'ip', timeout: int = 3) -> Tuple[bool, Optional[str]]:
        """Check if target is reachable before scanning"""
        try:
            if target_type == 'ip':
                # Try to ping or connect
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((target, 80))  # Try port 80
                sock.close()
                if result == 0:
                    return True, None
                else:
                    return False, f"Target {target} may not be reachable (connection test failed)"
            elif target_type == 'domain':
                # Try DNS resolution
                socket.gethostbyname(target)
                return True, None
        except socket.timeout:
            return False, f"Target {target} timeout - may be unreachable"
        except socket.gaierror:
            return False, f"Target {target} DNS resolution failed"
        except Exception as e:
            return False, f"Error checking target {target}: {str(e)}"
        
        return True, None
    
    def validate_targets(self, targets: List[str], check_availability: bool = False) -> Tuple[List[str], List[str]]:
        """Validate list of targets and return valid and invalid ones"""
        valid_targets = []
        invalid_targets = []
        
        for target in targets:
            target = target.strip()
            if not target:
                continue
            
            # Determine target type
            try:
                ipaddress.ip_address(target)
                target_type = 'ip'
                is_valid, error = self.validate_ip(target)
            except ValueError:
                target_type = 'domain'
                is_valid, error = self.validate_domain(target)
            
            if not is_valid:
                invalid_targets.append(f"{target} ({error})")
                self.warnings.append(f"{YELLOW}[WARN]{RESET} {target}: {error}")
                continue
            
            # Optional availability check
            if check_availability:
                is_available, error = self.check_target_availability(target, target_type)
                if not is_available:
                    self.warnings.append(f"{YELLOW}[WARN]{RESET} {target}: {error}")
            
            valid_targets.append(target)
        
        return valid_targets, invalid_targets
    
    def check_network_connectivity(self) -> Tuple[bool, Optional[str]]:
        """Check if network connectivity is available"""
        try:
            # Try to connect to a reliable DNS server
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2)
            sock.connect(('8.8.8.8', 53))
            sock.close()
            return True, None
        except Exception:
            return False, "No network connectivity detected"
    
    def check_dns_resolution(self) -> Tuple[bool, Optional[str]]:
        """Check if DNS resolution is working"""
        try:
            socket.gethostbyname('google.com')
            return True, None
        except Exception:
            return False, "DNS resolution not working"
    
    def print_warnings(self):
        """Print all collected warnings"""
        if self.warnings:
            print(f"\n{YELLOW}{'='*60}{RESET}")
            print(f"{YELLOW}Security Warnings:{RESET}")
            print(f"{YELLOW}{'='*60}{RESET}")
            for warning in self.warnings:
                print(warning)
            print(f"{YELLOW}{'='*60}{RESET}\n")
    
    def print_errors(self):
        """Print all collected errors"""
        if self.errors:
            print(f"\n{RED}{'='*60}{RESET}")
            print(f"{RED}Security Errors:{RESET}")
            print(f"{RED}{'='*60}{RESET}")
            for error in self.errors:
                print(error)
            print(f"{RED}{'='*60}{RESET}\n")


class BlacklistProtection:
    """Protection against scanning blacklisted targets"""
    
    def __init__(self, blacklist_file: Optional[str] = None):
        self.blacklisted_ips = set()
        self.blacklisted_domains = set()
        
        if blacklist_file and Path(blacklist_file).exists():
            self.load_blacklist(blacklist_file)
    
    def load_blacklist(self, filename: str):
        """Load blacklist from file"""
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    # Try to parse as IP
                    try:
                        ip = ipaddress.ip_address(line)
                        self.blacklisted_ips.add(str(ip))
                    except ValueError:
                        # Assume it's a domain
                        self.blacklisted_domains.add(line.lower())
        except Exception as e:
            print(f"{YELLOW}[WARN]{RESET} Failed to load blacklist: {e}")
    
    def is_blacklisted(self, target: str) -> Tuple[bool, Optional[str]]:
        """Check if target is blacklisted"""
        # Check IP blacklist
        try:
            ip = ipaddress.ip_address(target)
            if str(ip) in self.blacklisted_ips:
                return True, f"IP {target} is in blacklist"
        except ValueError:
            pass
        
        # Check domain blacklist
        if target.lower() in self.blacklisted_domains:
            return True, f"Domain {target} is in blacklist"
        
        return False, None
    
    def filter_blacklisted(self, targets: List[str]) -> Tuple[List[str], List[str]]:
        """Filter out blacklisted targets"""
        valid_targets = []
        blacklisted_targets = []
        
        for target in targets:
            is_blacklisted, reason = self.is_blacklisted(target)
            if is_blacklisted:
                blacklisted_targets.append(f"{target} ({reason})")
            else:
                valid_targets.append(target)
        
        return valid_targets, blacklisted_targets


def perform_security_checks(targets: List[str], check_network: bool = True, 
                           check_availability: bool = False) -> SecurityValidator:
    """Perform all security checks before scanning"""
    validator = SecurityValidator()
    
    # Check permissions
    has_perms, perm_msg = validator.check_permissions()
    if perm_msg:
        validator.warnings.append(f"{YELLOW}[WARN]{RESET} {perm_msg}")
    
    # Check network connectivity
    if check_network:
        is_connected, error = validator.check_network_connectivity()
        if not is_connected:
            validator.errors.append(f"{RED}[ERROR]{RESET} {error}")
        
        dns_works, error = validator.check_dns_resolution()
        if not dns_works:
            validator.warnings.append(f"{YELLOW}[WARN]{RESET} {error}")
    
    # Validate targets
    valid_targets, invalid_targets = validator.validate_targets(targets, check_availability)
    
    if invalid_targets:
        print(f"{YELLOW}[WARN]{RESET} {len(invalid_targets)} invalid targets found")
    
    return validator

