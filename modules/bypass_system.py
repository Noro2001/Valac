"""
Shodan Bypass System - Advanced rate limit bypass techniques
Integrated into Valac Scanner Module
"""

import requests
import time
import random
import json
import os
import threading
from collections import deque
from typing import Optional, Dict, Any, List

# Color codes
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
BLUE = "\033[94m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
RESET = "\033[0m"


class UserAgentGenerator:
    """Generate random user agents for session rotation"""
    
    def __init__(self):
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/119.0',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/119.0',
        ]
    
    def get_random(self):
        return random.choice(self.user_agents)


class SessionManager:
    """Manage multiple sessions with rotation"""
    
    def __init__(self, num_sessions=10):
        self.sessions = []
        self.current_index = 0
        self.lock = threading.Lock()
        self.ua_generator = UserAgentGenerator()
        self.create_sessions(num_sessions)
    
    def create_sessions(self, num):
        """Create multiple sessions with different headers"""
        for i in range(num):
            session = requests.Session()
            session.headers.update({
                'User-Agent': self.ua_generator.get_random(),
                'Accept': 'application/json, text/plain, */*',
                'Accept-Language': random.choice(['en-US,en;q=0.9', 'ru-RU,ru;q=0.8,en;q=0.3']),
                'Connection': 'keep-alive',
            })
            self.sessions.append(session)
    
    def get_session(self):
        """Get next session in rotation"""
        with self.lock:
            session = self.sessions[self.current_index]
            self.current_index = (self.current_index + 1) % len(self.sessions)
            return session


class AdvancedRateLimiter:
    """Advanced rate limiter with adaptive delays"""
    
    def __init__(self, requests_per_minute=30):
        self.max_requests = requests_per_minute
        self.request_times = deque()
        self.lock = threading.Lock()
        self.consecutive_429 = 0
        self.last_429_time = 0
    
    def wait_if_needed(self):
        """Wait if rate limit would be exceeded"""
        with self.lock:
            now = time.time()
            while self.request_times and now - self.request_times[0] > 60:
                self.request_times.popleft()
            
            if len(self.request_times) >= self.max_requests:
                sleep_time = 60 - (now - self.request_times[0]) + 0.5
                if sleep_time > 0:
                    time.sleep(sleep_time)
                    now = time.time()
                    while self.request_times and now - self.request_times[0] > 60:
                        self.request_times.popleft()
            
            self.request_times.append(now)
            
            if self.consecutive_429 > 0:
                extra_delay = min(self.consecutive_429 * 3, 60)
                time.sleep(extra_delay)
    
    def record_429(self):
        """Record a 429 error"""
        with self.lock:
            self.consecutive_429 += 1
            self.last_429_time = time.time()
    
    def reset_429(self):
        """Reset 429 counter"""
        with self.lock:
            if time.time() - self.last_429_time > 60:
                self.consecutive_429 = max(0, self.consecutive_429 - 1)


class CacheManager:
    """Manage cached results"""
    
    def __init__(self, cache_file='shodan_cache.json', max_age_hours=24):
        self.cache_file = cache_file
        self.max_age = max_age_hours * 3600
        self.cache = {}
        self.lock = threading.Lock()
        self.load_cache()
    
    def load_cache(self):
        """Load cache from file"""
        if os.path.exists(self.cache_file):
            try:
                with open(self.cache_file, 'r') as f:
                    self.cache = json.load(f)
            except (FileNotFoundError, json.JSONDecodeError, IOError):
                self.cache = {}
    
    def save_cache(self):
        """Save cache to file"""
        with self.lock:
            try:
                with open(self.cache_file, 'w') as f:
                    json.dump(self.cache, f, indent=2)
            except (IOError, OSError, PermissionError):
                # Silently ignore cache save errors
                pass
    
    def get(self, ip):
        """Get cached data for IP"""
        with self.lock:
            if ip in self.cache:
                entry = self.cache[ip]
                age = time.time() - entry['timestamp']
                if age < self.max_age:
                    return entry['data']
        return None
    
    def set(self, ip, data):
        """Cache data for IP"""
        with self.lock:
            self.cache[ip] = {
                'data': data,
                'timestamp': time.time()
            }


class ProxyManager:
    """Manage proxy rotation"""
    
    def __init__(self, proxy_file=None):
        self.proxies = []
        self.current_index = 0
        self.lock = threading.Lock()
        
        if proxy_file and os.path.exists(proxy_file):
            self.load_proxies(proxy_file)
    
    def load_proxies(self, filename):
        """Load proxies from file"""
        try:
            with open(filename, 'r') as f:
                self.proxies = [line.strip() for line in f if line.strip()]
        except (FileNotFoundError, IOError, PermissionError):
            # Silently ignore proxy file errors
            pass
    
    def get_proxy(self):
        """Get next proxy"""
        if not self.proxies:
            return None
        
        with self.lock:
            proxy = self.proxies[self.current_index]
            self.current_index = (self.current_index + 1) % len(self.proxies)
            return {'http': proxy, 'https': proxy}


class BypassSystem:
    """Complete Shodan Bypass System"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.session_manager = SessionManager(config.get('num_sessions', 10))
        self.rate_limiter = AdvancedRateLimiter(config.get('requests_per_minute', 30))
        self.cache_manager = CacheManager(
            config.get('cache_file', 'shodan_cache.json'),
            config.get('cache_hours', 24)
        )
        self.proxy_manager = ProxyManager(config.get('proxy_file'))
        self.use_proxy = config.get('use_proxy', False)
        
        self.stats = {
            'total': 0,
            'success': 0,
            'cached': 0,
            'failed': 0,
            'rate_limited': 0
        }
        self.stats_lock = threading.Lock()
    
    def fetch_with_bypass(self, ip: str, retry_count: int = 3) -> Optional[Dict[str, Any]]:
        """Fetch data for IP with bypass techniques"""
        cached_data = self.cache_manager.get(ip)
        if cached_data:
            with self.stats_lock:
                self.stats['cached'] += 1
            return {'ip': ip, 'data': cached_data, 'source': 'cache'}
        
        for attempt in range(retry_count):
            try:
                self.rate_limiter.wait_if_needed()
                session = self.session_manager.get_session()
                proxy = self.proxy_manager.get_proxy() if self.use_proxy else None
                
                delay = random.uniform(
                    self.config.get('min_delay', 1.0),
                    self.config.get('max_delay', 3.0)
                )
                time.sleep(delay)
                
                url = f"https://internetdb.shodan.io/{ip}"
                response = session.get(url, timeout=self.config.get('timeout', 15), proxies=proxy)
                
                if response.status_code == 200:
                    data = response.json()
                    self.cache_manager.set(ip, data)
                    self.rate_limiter.reset_429()
                    with self.stats_lock:
                        self.stats['success'] += 1
                    return {'ip': ip, 'data': data, 'source': 'api'}
                
                elif response.status_code == 404:
                    with self.stats_lock:
                        self.stats['failed'] += 1
                    return None
                
                elif response.status_code == 429:
                    self.rate_limiter.record_429()
                    with self.stats_lock:
                        self.stats['rate_limited'] += 1
                    backoff = (2 ** attempt) * 5 + random.uniform(0, 5)
                    time.sleep(backoff)
                    continue
                
                else:
                    if attempt < retry_count - 1:
                        time.sleep((2 ** attempt) * 2)
                        continue
                    with self.stats_lock:
                        self.stats['failed'] += 1
                    return None
            
            except Exception:
                if attempt < retry_count - 1:
                    time.sleep(2 ** attempt)
                    continue
        
        with self.stats_lock:
            self.stats['failed'] += 1
        return None
    
    def get_stats(self) -> Dict[str, int]:
        """Get current statistics"""
        with self.stats_lock:
            return self.stats.copy()
    
    def save_cache(self):
        """Save cache to file"""
        self.cache_manager.save_cache()

