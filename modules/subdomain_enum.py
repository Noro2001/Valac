"""
Subdomain Enumeration Module
Supports passive collection, brute force, and validation
Enhanced with resource management and performance monitoring
"""

import asyncio
import aiohttp
import aiodns
import json
import re
import time
import os
from pathlib import Path
from typing import Iterable, List, Optional, Set, Tuple, Dict
from tqdm.asyncio import tqdm as atqdm
from collections import deque

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

# Color codes
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"
RESET = "\033[0m"

# Resource limits
MAX_CONCURRENT_DNS = 500  # Maximum concurrent DNS queries
MAX_CONCURRENT_HTTP = 200  # Maximum concurrent HTTP requests
MEMORY_CHECK_INTERVAL = 500  # Check memory every N operations

try:
    import dns.resolver
except ImportError:
    dns = None


async def resolve_host(resolver: aiodns.DNSResolver, host: str, timeout: float = 10.0) -> Tuple[str, List[str]]:
    """Resolve host with timeout protection"""
    ips = []
    try:
        # Use asyncio.wait_for for timeout protection
        a_records = await asyncio.wait_for(resolver.query(host, 'A'), timeout=timeout)
        ips.extend([r.host for r in a_records])
    except asyncio.TimeoutError:
        pass  # Timeout is expected for non-existent hosts
    except Exception:
        # Catch all DNS-related errors (aiodns raises various exceptions)
        # This includes aiodns.error.DNSError and other DNS errors
        pass  # DNS error is expected for non-existent hosts
    
    try:
        aaaa_records = await asyncio.wait_for(resolver.query(host, 'AAAA'), timeout=timeout)
        ips.extend([r.host for r in aaaa_records])
    except asyncio.TimeoutError:
        pass
    except Exception:
        # Catch all DNS-related errors
        pass
    
    return host, sorted(set(ips))


async def fetch_title(session: aiohttp.ClientSession, url: str, timeout: float = 10.0) -> Tuple[str, Optional[int], Optional[str]]:
    """Fetch page title with timeout and error handling"""
    try:
        async with asyncio.wait_for(session.get(url, allow_redirects=False), timeout=timeout) as resp:
            code = resp.status
            # Limit response size
            text = await resp.text(errors="ignore")
            if len(text) > 100000:  # Limit to 100KB for title extraction
                text = text[:100000]
            m = re.search(r"<title[^>]*>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
            title = m.group(1).strip() if m else ""
            title = re.sub(r"\s+", " ", title)[:200]
            return url, code, title
    except asyncio.TimeoutError:
        return url, None, None
    except aiohttp.ClientError:
        return url, None, None
    except Exception:
        return url, None, None


async def http_inventory(hosts: List[str], concurrency: int, timeout: int) -> List[Tuple[str, Optional[int], Optional[str]]]:
    """HTTP inventory with resource management"""
    # Limit concurrency
    actual_concurrency = min(concurrency, MAX_CONCURRENT_HTTP)
    if concurrency > MAX_CONCURRENT_HTTP:
        print(f"{YELLOW}[INFO]{RESET} HTTP concurrency limited to {actual_concurrency} (max: {MAX_CONCURRENT_HTTP})")
    
    # Limit connector pool
    max_connections = min(actual_concurrency * 2, 100)
    connector = aiohttp.TCPConnector(
        ssl=False,
        limit=max_connections,
        limit_per_host=min(actual_concurrency, 20),
        ttl_dns_cache=300,
        force_close=True
    )
    tout = aiohttp.ClientTimeout(total=timeout, connect=5)
    headers = {"User-Agent": "Valac/1.0"}
    out = []
    total = len(hosts) * 2  # HTTP + HTTPS
    request_count = 0
    start_time = time.time()
    
    pbar = atqdm(
        total=total,
        desc=f"{YELLOW}[SUBDOMAIN]{RESET} HTTP inventory",
        unit="request",
        bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]',
        colour='blue'
    )

    async with aiohttp.ClientSession(connector=connector, timeout=tout, headers=headers) as session:
        # Process in batches to manage memory
        batch_size = actual_concurrency * 2
        for i in range(0, len(hosts), batch_size):
            batch_hosts = hosts[i:i+batch_size]
            tasks = []
            for h in batch_hosts:
                tasks.append(fetch_title(session, f"https://{h}"))
                tasks.append(fetch_title(session, f"http://{h}"))
            
            # Process batch with semaphore
            sem = asyncio.Semaphore(actual_concurrency * 2)
            async def bounded_task(task):
                async with sem:
                    return await task
            
            results = await asyncio.gather(*[bounded_task(t) for t in tasks], return_exceptions=True)
            
            for r in results:
                if isinstance(r, tuple):
                    out.append(r)
                request_count += 1
                pbar.update(1)
                
                # Periodic stats update
                if request_count % 50 == 0:
                    elapsed = time.time() - start_time
                    rate = request_count / elapsed if elapsed > 0 else 0
                    pbar.set_postfix({
                        'Found': sum(1 for _, c, _ in out if c is not None),
                        'Rate': f"{rate:.1f}/s"
                    })
    
    pbar.close()
    return out


CRT_URL = "https://crt.sh/?q=%25.{domain}&output=json"


async def fetch_crtsh(domain: str) -> Set[str]:
    names: Set[str] = set()
    timeout = aiohttp.ClientTimeout(total=30)
    headers = {"User-Agent": "Valac/1.0"}
    async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
        async with session.get(CRT_URL.format(domain=domain)) as resp:
            if resp.status != 200:
                return names
            try:
                data = await resp.json(content_type=None)
            except Exception:
                text = await resp.text()
                try:
                    data = json.loads(text)
                except Exception:
                    return names
            for row in data:
                v = row.get("name_value") or ""
                v = v.replace("*.", "")
                for part in v.splitlines():
                    part = part.strip().lower()
                    if part.endswith("." + domain) or part == domain:
                        names.add(part)
    return names


def load_wordlist(path: Path) -> List[str]:
    out = []
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            w = line.strip()
            if not w or w.startswith("#"):
                continue
            out.append(w)
    return out


async def validate_hosts(hosts: Iterable[str], concurrency: int, resolvers: Optional[List[str]]) -> Dict[str, List[str]]:
    """Validate hosts with resource management"""
    # Limit concurrency to prevent resource exhaustion
    actual_concurrency = min(concurrency, MAX_CONCURRENT_DNS)
    if concurrency > MAX_CONCURRENT_DNS:
        print(f"{YELLOW}[INFO]{RESET} Concurrency limited to {actual_concurrency} (max: {MAX_CONCURRENT_DNS})")
    
    r = aiodns.DNSResolver()
    if resolvers:
        r.nameservers = resolvers
    
    # Use semaphore for rate limiting
    sem = asyncio.Semaphore(actual_concurrency)
    results: Dict[str, List[str]] = {}
    operation_count = 0
    
    hosts_list = list(hosts)
    total = len(hosts_list)
    start_time = time.time()
    
    pbar = atqdm(
        total=total,
        desc=f"{YELLOW}[SUBDOMAIN]{RESET} Validating DNS",
        unit="host",
        bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]',
        colour='yellow'
    )

    async def task(h: str):
        nonlocal operation_count
        async with sem:
            try:
                host, ips = await asyncio.wait_for(resolve_host(r, h), timeout=10.0)
                if ips:
                    results[host] = ips
            except asyncio.TimeoutError:
                pass
            except Exception:
                pass
            finally:
                operation_count += 1
                pbar.update(1)
                
                # Periodic memory check
                if PSUTIL_AVAILABLE and operation_count % MEMORY_CHECK_INTERVAL == 0:
                    try:
                        process = psutil.Process(os.getpid())
                        memory_mb = process.memory_info().rss / 1024 / 1024
                        if memory_mb > 2048:  # Warn if > 2GB
                            print(f"\n{YELLOW}[WARN]{RESET} High memory usage: {memory_mb:.1f}MB")
                    except (OSError, AttributeError):
                        # Silently ignore memory check errors
                        pass
                
                elapsed = time.time() - start_time
                rate = operation_count / elapsed if elapsed > 0 else 0
                pbar.set_postfix({
                    'Valid': len(results),
                    'Rate': f"{rate:.1f}/s"
                })

    # Process in batches to prevent memory issues
    batch_size = actual_concurrency * 2
    for i in range(0, len(hosts_list), batch_size):
        batch = hosts_list[i:i+batch_size]
        tasks = [asyncio.create_task(task(h)) for h in batch]
        await asyncio.gather(*tasks, return_exceptions=True)
    
    pbar.close()
    return results


def write_list(path: Path, items: Iterable[str]):
    with path.open("w", encoding="utf-8") as f:
        for it in items:
            f.write(str(it).strip() + "\n")


def write_resolved(path: Path, mapping: Dict[str, List[str]]):
    with path.open("w", encoding="utf-8") as f:
        for h, ips in sorted(mapping.items()):
            f.write(h + " " + " ".join(ips) + "\n")


class SubdomainEnumModule:
    async def run_async(self, args):
        outdir = Path(args.out)
        outdir.mkdir(parents=True, exist_ok=True)

        resolvers = None
        if getattr(args, "resolvers", None):
            rp = Path(args.resolvers)
            if rp.exists():
                resolvers = [x.strip() for x in rp.read_text().splitlines() if x.strip()]

        raw: Set[str] = set()
        if args.subdomain_mode == "passive":
            print(f"{YELLOW}[INFO]{RESET} Fetching subdomains from Certificate Transparency...")
            names = await fetch_crtsh(args.domain)
            raw |= names
        elif args.subdomain_mode == "brute":
            print(f"{YELLOW}[INFO]{RESET} Loading wordlist...")
            wordlist_path = Path(args.wordlist)
            if not wordlist_path.exists():
                print(f"{RED}[ERROR]{RESET} Wordlist file not found: {args.wordlist}")
                return
            words = load_wordlist(wordlist_path)
            if not words:
                print(f"{RED}[ERROR]{RESET} Wordlist is empty or invalid")
                return
            print(f"{GREEN}[INFO]{RESET} Loaded {len(words)} words")
            raw |= {f"{w.strip().lower()}.{args.domain}" for w in words}
        elif args.subdomain_mode == "validate":
            print(f"{YELLOW}[INFO]{RESET} Reading input file...")
            input_path = Path(args.input)
            if not input_path.exists():
                print(f"{RED}[ERROR]{RESET} Input file not found: {args.input}")
                return
            raw |= {x.strip().lower() for x in input_path.read_text().splitlines() if x.strip()}

        # Escape domain for regex if it exists
        if hasattr(args, 'domain') and args.domain:
            domain_escaped = re.escape(args.domain)
            domain_pattern = domain_escaped
        else:
            domain_pattern = r"[a-z0-9.-]+"
        
        # Filter subdomains matching the domain pattern
        cleaned = []
        for x in raw:
            if hasattr(args, 'domain') and args.domain:
                # Check if subdomain ends with the domain
                if x.endswith("." + args.domain) or x == args.domain:
                    cleaned.append(x)
            else:
                # Generic pattern matching
                if re.fullmatch(r"[a-z0-9_.-]+\." + domain_pattern, x):
                    cleaned.append(x)
        cleaned = sorted(set(cleaned))
        write_list(outdir / "subs_raw.txt", cleaned)
        print(f"{GREEN}[INFO]{RESET} Raw subdomains: {len(cleaned)}")

        print(f"{YELLOW}[INFO]{RESET} Validating DNS records...")
        valid = await validate_hosts(cleaned, args.threads, resolvers)
        write_resolved(outdir / "subs_resolved.txt", valid)
        print(f"{GREEN}[INFO]{RESET} Valid subdomains (A/AAAA): {len(valid)}")

        if args.http and valid:
            print(f"{YELLOW}[INFO]{RESET} Performing HTTP inventory...")
            hosts = sorted(valid.keys())
            web = await http_inventory(hosts, args.threads, timeout=10)
            with (outdir / "web_hosts.txt").open("w", encoding="utf-8") as f:
                for url, code, title in web:
                    if code is not None:
                        f.write(f"{url}\t{code}\t{title or ''}\n")
            print(f"{GREEN}[INFO]{RESET} HTTP records: {sum(1 for _,c,_ in web if c is not None)}")
        
        print(f"{GREEN}[SUCCESS]{RESET} Results saved to {outdir}")

    def run(self, args):
        try:
            asyncio.run(self.run_async(args))
        except KeyboardInterrupt:
            print(f"\n{YELLOW}[WARN]{RESET} Operation interrupted")
