"""
Fuzzer Module - Directory and VHost Fuzzing
"""

import asyncio
import aiohttp
import aiodns
from urllib.parse import urljoin
from typing import Set, List

# Color codes
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
RESET = "\033[0m"

DEFAULT_CODES = {200, 204, 301, 302, 307, 401, 403}


async def fetch(session: aiohttp.ClientSession, method: str, url: str, **kwargs):
    try:
        async with session.request(method, url, allow_redirects=False, **kwargs) as resp:
            text = await resp.text(errors="ignore")
            return resp.status, len(text), resp.headers.get("Content-Length"), resp.headers.get("Location")
    except Exception:
        return None, None, None, None


async def worker_dir(queue: asyncio.Queue, session: aiohttp.ClientSession, base_url: str, statuses: Set[int], exts: List[str]):
    while True:
        path = await queue.get()
        if path is None:
            queue.task_done()
            break

        candidates = [path]
        for ext in exts:
            if not path.endswith(f".{ext}"):
                candidates.append(f"{path}.{ext}")

        for cand in candidates:
            url = urljoin(base_url.rstrip("/") + "/", cand.lstrip("/"))
            code, size, clen, loc = await fetch(session, "GET", url)
            if code in statuses:
                print(f"[{code}] {url}  size={size}  cl={clen}  loc={loc}")
        queue.task_done()


async def worker_vhost(queue: asyncio.Queue, session: aiohttp.ClientSession, base_url: str, base_ip: str, statuses: Set[int], domain: str):
    while True:
        host = await queue.get()
        if host is None:
            queue.task_done()
            break

        headers = {"Host": f"{host}.{domain}"}
        try:
            target_url = base_url.replace("://"+domain, "://"+base_ip)
            code, size, clen, loc = await fetch(session, "GET", target_url, headers=headers)
            if code in statuses:
                print(f"[{code}] {headers['Host']} -> {target_url}  size={size}  cl={clen}  loc={loc}")
        except Exception:
            pass
        queue.task_done()


async def run_dir_async(args):
    import os
    if not os.path.exists(args.w):
        print(f"{RED}[ERROR]{RESET} Wordlist file not found: {args.w}")
        return
    
    connector = aiohttp.TCPConnector(ssl=False, limit=args.t)
    timeout = aiohttp.ClientTimeout(total=args.timeout)
    async with aiohttp.ClientSession(connector=connector, timeout=timeout, headers={"User-Agent": args.ua}) as session:
        q = asyncio.Queue()
        try:
            with open(args.w, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    w = line.strip()
                    if not w or w.startswith("#"):
                        continue
                    q.put_nowait(w)
        except Exception as e:
            print(f"{RED}[ERROR]{RESET} Error reading wordlist: {e}")
            return

        workers = [asyncio.create_task(worker_dir(q, session, args.u, set(args.S), args.e)) for _ in range(args.t)]
        await q.join()
        for _ in workers:
            q.put_nowait(None)
        await asyncio.gather(*workers, return_exceptions=True)


async def run_vhost_async(args):
    import os
    if not os.path.exists(args.w):
        print(f"{RED}[ERROR]{RESET} Wordlist file not found: {args.w}")
        return
    
    connector = aiohttp.TCPConnector(ssl=False, limit=args.t)
    timeout = aiohttp.ClientTimeout(total=args.timeout)
    async with aiohttp.ClientSession(connector=connector, timeout=timeout, headers={"User-Agent": args.ua}) as session:
        q = asyncio.Queue()
        try:
            with open(args.w, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    w = line.strip()
                    if not w or w.startswith("#"):
                        continue
                    q.put_nowait(w)
        except Exception as e:
            print(f"{RED}[ERROR]{RESET} Error reading wordlist: {e}")
            return
        workers = [asyncio.create_task(worker_vhost(q, session, args.u, args.b, set(args.S), args.domain)) for _ in range(args.t)]
        await q.join()
        for _ in workers:
            q.put_nowait(None)
        await asyncio.gather(*workers, return_exceptions=True)


class FuzzerModule:
    async def run_async(self, args):
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

