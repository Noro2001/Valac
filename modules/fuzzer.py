"""
Fuzzer Module - Directory and VHost Fuzzing
Enhanced with resource management and performance monitoring
"""

import asyncio
import aiohttp
import aiodns
import time
import os
from urllib.parse import urljoin
from typing import Set, List, Optional
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

DEFAULT_CODES = {200, 204, 301, 302, 307, 401, 403}

# Resource limits
MAX_QUEUE_SIZE = 10000  # Maximum items in queue
MAX_MEMORY_MB = 2048  # Maximum memory usage in MB
MEMORY_CHECK_INTERVAL = 100  # Check memory every N requests


class ResourceMonitor:
    """Monitor system resources during fuzzing"""
    def __init__(self):
        self.start_time = time.time()
        self.request_count = 0
        self.error_count = 0
        self.success_count = 0
        self.memory_samples = deque(maxlen=100)
        self.last_memory_check = 0
        
    def check_memory(self) -> float:
        """Check current memory usage in MB"""
        if not PSUTIL_AVAILABLE:
            return 0
        try:
            process = psutil.Process(os.getpid())
            memory_mb = process.memory_info().rss / 1024 / 1024
            self.memory_samples.append(memory_mb)
            self.last_memory_check = time.time()
            return memory_mb
        except (OSError, AttributeError):
            # Silently ignore memory check errors
            return 0
    
    def get_stats(self) -> dict:
        """Get current statistics"""
        elapsed = time.time() - self.start_time
        avg_memory = sum(self.memory_samples) / len(self.memory_samples) if self.memory_samples else 0
        return {
            'elapsed': elapsed,
            'requests': self.request_count,
            'success': self.success_count,
            'errors': self.error_count,
            'rate': self.request_count / elapsed if elapsed > 0 else 0,
            'memory_mb': avg_memory,
            'max_memory_mb': max(self.memory_samples) if self.memory_samples else 0
        }


async def fetch(session: aiohttp.ClientSession, method: str, url: str, timeout: Optional[float] = None, max_retries: int = 2, **kwargs):
    """Fetch URL with timeout, error handling, and retry logic"""
    last_error = None
    
    for attempt in range(max_retries + 1):
        try:
            fetch_timeout = aiohttp.ClientTimeout(total=timeout, connect=5) if timeout else aiohttp.ClientTimeout(total=15, connect=5)
            async with session.request(method, url, allow_redirects=False, timeout=fetch_timeout, **kwargs) as resp:
                # Limit response size to prevent memory issues
                max_size = 1024 * 1024  # 1MB
                text = await resp.read()
                if len(text) > max_size:
                    text = text[:max_size]
                else:
                    text = text.decode('utf-8', errors='ignore')
                return resp.status, len(text), resp.headers.get("Content-Length"), resp.headers.get("Location")
        except asyncio.TimeoutError:
            last_error = "Timeout"
            if attempt < max_retries:
                await asyncio.sleep(0.5 * (attempt + 1))  # Exponential backoff
                continue
        except aiohttp.ClientError as e:
            last_error = f"Client error: {str(e)}"
            if attempt < max_retries and "429" not in str(e):  # Don't retry rate limits
                await asyncio.sleep(0.5 * (attempt + 1))
                continue
            break
        except Exception as e:
            last_error = f"Unexpected error: {str(e)}"
            break
    
    # Log error for debugging (can be disabled in production)
    return None, None, None, None


async def worker_dir(queue: asyncio.Queue, session: aiohttp.ClientSession, base_url: str, 
                     statuses: Set[int], exts: List[str], monitor: ResourceMonitor, 
                     timeout: float, pbar=None):
    found_count = 0
    while True:
        try:
            path = await asyncio.wait_for(queue.get(), timeout=1.0)
        except asyncio.TimeoutError:
            continue
            
        if path is None:
            queue.task_done()
            break

        candidates = [path]
        for ext in exts:
            if not path.endswith(f".{ext}"):
                candidates.append(f"{path}.{ext}")

        for cand in candidates:
            url = urljoin(base_url.rstrip("/") + "/", cand.lstrip("/"))
            code, size, clen, loc = await fetch(session, "GET", url, timeout=timeout)
            monitor.request_count += 1
            
            if code in statuses:
                found_count += 1
                monitor.success_count += 1
                print(f"[{code}] {url}  size={size}  cl={clen}  loc={loc}")
            elif code is None:
                monitor.error_count += 1
            
            # Periodic memory check
            if monitor.request_count % MEMORY_CHECK_INTERVAL == 0:
                memory = monitor.check_memory()
                if memory > MAX_MEMORY_MB:
                    print(f"{YELLOW}[WARN]{RESET} High memory usage: {memory:.1f}MB")
                    
        if pbar:
            stats = monitor.get_stats()
            pbar.update(1)
            pbar.set_postfix({
                'Found': found_count,
                'Rate': f"{stats['rate']:.1f}/s",
                'Mem': f"{stats['memory_mb']:.0f}MB"
            })
        queue.task_done()


async def worker_vhost(queue: asyncio.Queue, session: aiohttp.ClientSession, base_url: str, 
                       base_ip: str, statuses: Set[int], domain: str, monitor: ResourceMonitor,
                       timeout: float, pbar=None):
    found_count = 0
    while True:
        try:
            host = await asyncio.wait_for(queue.get(), timeout=1.0)
        except asyncio.TimeoutError:
            continue
            
        if host is None:
            queue.task_done()
            break

        headers = {"Host": f"{host}.{domain}"}
        try:
            target_url = base_url.replace("://"+domain, "://"+base_ip)
            code, size, clen, loc = await fetch(session, "GET", target_url, timeout=timeout, headers=headers)
            monitor.request_count += 1
            
            if code in statuses:
                found_count += 1
                monitor.success_count += 1
                print(f"[{code}] {headers['Host']} -> {target_url}  size={size}  cl={clen}  loc={loc}")
            elif code is None:
                monitor.error_count += 1
        except Exception:
            monitor.error_count += 1
            
        # Periodic memory check
        if monitor.request_count % MEMORY_CHECK_INTERVAL == 0:
            memory = monitor.check_memory()
            if memory > MAX_MEMORY_MB:
                print(f"{YELLOW}[WARN]{RESET} High memory usage: {memory:.1f}MB")
                
        if pbar:
            stats = monitor.get_stats()
            pbar.update(1)
            pbar.set_postfix({
                'Found': found_count,
                'Rate': f"{stats['rate']:.1f}/s",
                'Mem': f"{stats['memory_mb']:.0f}MB"
            })
        queue.task_done()


async def run_dir_async(args):
    import os
    if not os.path.exists(args.w):
        print(f"{RED}[ERROR]{RESET} Wordlist file not found: {args.w}")
        return
    
    # Initialize resource monitor
    monitor = ResourceMonitor()
    
    # Count total words first
    total_words = 0
    try:
        with open(args.w, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                w = line.strip()
                if w and not w.startswith("#"):
                    total_words += 1
    except Exception as e:
        print(f"{RED}[ERROR]{RESET} Error reading wordlist: {e}")
        return
    
    if total_words == 0:
        print(f"{YELLOW}[WARN]{RESET} Wordlist is empty")
        return
    
    print(f"{CYAN}[INFO]{RESET} Loaded {total_words} words from wordlist")
    print(f"{CYAN}[INFO]{RESET} Concurrency: {args.t}, Timeout: {args.timeout}s")
    
    pbar = atqdm(
        total=total_words,
        desc=f"{YELLOW}[FUZZ]{RESET} Directory fuzzing",
        unit="path",
        bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]',
        colour='magenta'
    )
    
    # Limit connector pool size to prevent resource exhaustion
    max_connections = min(args.t * 2, 100)  # Cap at 100 connections
    connector = aiohttp.TCPConnector(
        ssl=False, 
        limit=max_connections,
        limit_per_host=min(args.t, 20),  # Limit per host
        ttl_dns_cache=300,
        force_close=True  # Close connections to free resources
    )
    timeout = aiohttp.ClientTimeout(total=args.timeout, connect=5)
    
    async with aiohttp.ClientSession(connector=connector, timeout=timeout, headers={"User-Agent": args.ua}) as session:
        # Use bounded queue to prevent memory issues
        q = asyncio.Queue(maxsize=MAX_QUEUE_SIZE)
        
        # Producer task to load words into queue
        async def producer():
            try:
                with open(args.w, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        w = line.strip()
                        if not w or w.startswith("#"):
                            continue
                        # Wait if queue is full
                        while q.qsize() >= MAX_QUEUE_SIZE:
                            await asyncio.sleep(0.1)
                        await q.put(w)
            except Exception as e:
                print(f"{RED}[ERROR]{RESET} Error reading wordlist: {e}")
            finally:
                # Signal workers to stop
                for _ in range(args.t):
                    await q.put(None)

        # Start producer
        producer_task = asyncio.create_task(producer())
        
        # Start workers
        workers = [
            asyncio.create_task(worker_dir(q, session, args.u, set(args.S), args.e, monitor, args.timeout, pbar)) 
            for _ in range(args.t)
        ]
        
        # Wait for producer to finish
        await producer_task
        
        # Wait for queue to be processed
        await q.join()
        
        # Wait for workers to finish
        await asyncio.gather(*workers, return_exceptions=True)
    
    pbar.close()
    
    # Print final statistics
    stats = monitor.get_stats()
    print(f"\n{CYAN}[STATS]{RESET} Fuzzing completed:")
    print(f"  Requests: {stats['requests']}")
    print(f"  Success: {stats['success']}")
    print(f"  Errors: {stats['errors']}")
    print(f"  Rate: {stats['rate']:.2f} req/s")
    print(f"  Memory: {stats['max_memory_mb']:.1f}MB peak")


async def run_vhost_async(args):
    import os
    if not os.path.exists(args.w):
        print(f"{RED}[ERROR]{RESET} Wordlist file not found: {args.w}")
        return
    
    # Initialize resource monitor
    monitor = ResourceMonitor()
    
    # Count total words first
    total_words = 0
    try:
        with open(args.w, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                w = line.strip()
                if w and not w.startswith("#"):
                    total_words += 1
    except Exception as e:
        print(f"{RED}[ERROR]{RESET} Error reading wordlist: {e}")
        return
    
    if total_words == 0:
        print(f"{YELLOW}[WARN]{RESET} Wordlist is empty")
        return
    
    print(f"{CYAN}[INFO]{RESET} Loaded {total_words} words from wordlist")
    print(f"{CYAN}[INFO]{RESET} Concurrency: {args.t}, Timeout: {args.timeout}s")
    
    pbar = atqdm(
        total=total_words,
        desc=f"{YELLOW}[FUZZ]{RESET} VHost fuzzing",
        unit="host",
        bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]',
        colour='cyan'
    )
    
    # Limit connector pool size
    max_connections = min(args.t * 2, 100)
    connector = aiohttp.TCPConnector(
        ssl=False,
        limit=max_connections,
        limit_per_host=min(args.t, 20),
        ttl_dns_cache=300,
        force_close=True
    )
    timeout = aiohttp.ClientTimeout(total=args.timeout, connect=5)
    
    async with aiohttp.ClientSession(connector=connector, timeout=timeout, headers={"User-Agent": args.ua}) as session:
        # Use bounded queue
        q = asyncio.Queue(maxsize=MAX_QUEUE_SIZE)
        
        # Producer task
        async def producer():
            try:
                with open(args.w, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        w = line.strip()
                        if not w or w.startswith("#"):
                            continue
                        while q.qsize() >= MAX_QUEUE_SIZE:
                            await asyncio.sleep(0.1)
                        await q.put(w)
            except Exception as e:
                print(f"{RED}[ERROR]{RESET} Error reading wordlist: {e}")
            finally:
                for _ in range(args.t):
                    await q.put(None)
        
        producer_task = asyncio.create_task(producer())
        
        workers = [
            asyncio.create_task(worker_vhost(q, session, args.u, args.b, set(args.S), args.domain, monitor, args.timeout, pbar)) 
            for _ in range(args.t)
        ]
        
        await producer_task
        await q.join()
        await asyncio.gather(*workers, return_exceptions=True)
    
    pbar.close()
    
    # Print final statistics
    stats = monitor.get_stats()
    print(f"\n{CYAN}[STATS]{RESET} VHost fuzzing completed:")
    print(f"  Requests: {stats['requests']}")
    print(f"  Success: {stats['success']}")
    print(f"  Errors: {stats['errors']}")
    print(f"  Rate: {stats['rate']:.2f} req/s")
    print(f"  Memory: {stats['max_memory_mb']:.1f}MB peak")


class FuzzerModule:
    async def run_async(self, args):
        # Check if psutil is available for resource monitoring
        if not PSUTIL_AVAILABLE:
            print(f"{YELLOW}[WARN]{RESET} psutil not installed. Resource monitoring disabled.")
            print(f"{YELLOW}[INFO]{RESET} Install with: pip install psutil")
        
        if args.fuzz_mode == "dir":
            if not hasattr(args, 'e') or args.e == "":
                args.e = []
            else:
                args.e = [x.strip() for x in args.e.split(",") if x.strip()]
            await run_dir_async(args)
        elif args.fuzz_mode == "vhost":
            if not getattr(args, "domain", None):
                import re
                m = re.search(r"https?://([^/]+)", args.u)
                if m:
                    args.domain = m.group(1)
            if not getattr(args, "domain", None):
                print(f"{RED}[ERROR]{RESET} --domain required or could not extract from -u")
                return
            await run_vhost_async(args)

    def run(self, args):
        try:
            asyncio.run(self.run_async(args))
        except KeyboardInterrupt:
            print(f"\n{YELLOW}[WARN]{RESET} Operation interrupted")

