"""
Subdomain Enumeration Module
Supports passive collection, brute force, and validation
"""

import asyncio
import aiohttp
import aiodns
import json
import re
from pathlib import Path
from typing import Iterable, List, Optional, Set, Tuple, Dict

# Color codes
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
RESET = "\033[0m"

try:
    import dns.resolver
except ImportError:
    dns = None


async def resolve_host(resolver: aiodns.DNSResolver, host: str) -> Tuple[str, List[str]]:
    ips = []
    try:
        a_records = await resolver.query(host, 'A')
        ips.extend([r.host for r in a_records])
    except Exception:
        pass
    try:
        aaaa_records = await resolver.query(host, 'AAAA')
        ips.extend([r.host for r in aaaa_records])
    except Exception:
        pass
    return host, sorted(set(ips))


async def fetch_title(session: aiohttp.ClientSession, url: str) -> Tuple[str, Optional[int], Optional[str]]:
    try:
        async with session.get(url, allow_redirects=False) as resp:
            code = resp.status
            text = await resp.text(errors="ignore")
            m = re.search(r"<title[^>]*>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
            title = m.group(1).strip() if m else ""
            title = re.sub(r"\s+", " ", title)[:200]
            return url, code, title
    except Exception:
        return url, None, None


async def http_inventory(hosts: List[str], concurrency: int, timeout: int) -> List[Tuple[str, Optional[int], Optional[str]]]:
    connector = aiohttp.TCPConnector(ssl=False, limit=concurrency)
    tout = aiohttp.ClientTimeout(total=timeout)
    headers = {"User-Agent": "Valak/1.0"}
    out = []

    async with aiohttp.ClientSession(connector=connector, timeout=tout, headers=headers) as session:
        tasks = []
        for h in hosts:
            tasks.append(fetch_title(session, f"https://{h}"))
            tasks.append(fetch_title(session, f"http://{h}"))
        for chunk in [tasks[i:i+concurrency*2] for i in range(0, len(tasks), concurrency*2)]:
            results = await asyncio.gather(*chunk, return_exceptions=True)
            for r in results:
                if isinstance(r, tuple):
                    out.append(r)
    return out


CRT_URL = "https://crt.sh/?q=%25.{domain}&output=json"


async def fetch_crtsh(domain: str) -> Set[str]:
    names: Set[str] = set()
    timeout = aiohttp.ClientTimeout(total=30)
    headers = {"User-Agent": "Valak/1.0"}
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
    r = aiodns.DNSResolver()
    if resolvers:
        r.nameservers = resolvers
    sem = asyncio.Semaphore(concurrency)
    results: Dict[str, List[str]] = {}

    async def task(h: str):
        async with sem:
            host, ips = await resolve_host(r, h)
            if ips:
                results[host] = ips

    tasks = [asyncio.create_task(task(h)) for h in hosts]
    await asyncio.gather(*tasks, return_exceptions=True)
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
