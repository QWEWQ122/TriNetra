############################################
#Coding: utf-8				               #
#Author : Debajyoti0-0                     #
#Version: 1.0                              #                                
#Github : https://github.com/Debajyoti0-0/ #
############################################

#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import html
import json
import random
import re
import sys
import time
import os
import shutil
from collections import deque
from pathlib import Path
from typing import Iterable, Mapping, MutableMapping, Set, Tuple, List, Dict, Optional
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse, urldefrag
from rich.console import Console
from rich.text import Text

# Banner for TRINETRA
console = Console()

banner = Text()
banner.append("\n")
banner.append("╔╦╗┬─┐┬╔╗╔┌─┐┌┬┐┬─┐┌─┐\n", style="bold red")
banner.append(" ║ ├┬┘│║║║├┤  │ ├┬┘├─┤\n", style="bold green")
banner.append(" ╩ ┴└─┴╝╚╝└─┘ ┴ ┴└─┴ ┴\n", style="bold blue")
banner.append("T h e   T h i r d   E y e   O f   S e e   B e y o n d   T h e   S u r f a c e... 🔎 🌐\n", style="bold Cyan")
banner.append("\n")
banner.append("Author : ", style="bold green")
banner.append("Debajyoti0-0\n", style="white")
banner.append("Github : ", style="bold green")
banner.append("https://github.com/Debajyoti0-0\n", style="white")
#banner.append("\n")
terminal_width = shutil.get_terminal_size().columns
separator = "=" * terminal_width
banner.append(separator, style="white")
banner.append("\n")

# Third-party
try:
    import requests
except ImportError:
    print("[!] Missing dependency: requests. Please run: pip install requests", file=sys.stderr)
    sys.exit(1)

HTTPX_AVAILABLE = False
try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    pass

try:
    from bs4 import BeautifulSoup
except ImportError:
    print("[!] Missing dependency: beautifulsoup4. Please run: pip install beautifulsoup4", file=sys.stderr)
    sys.exit(1)

# LXML is a faster parser, optional but recommended
try:
    import lxml
    PARSER = "lxml"
except ImportError:
    PARSER = "html.parser"

# Rich for beautiful CLI UI
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

# ---------------------------------------------------------------------------
# CLI UI Initialization
# ---------------------------------------------------------------------------
class FallbackConsole:
    """A dummy console for when 'rich' is not installed."""
    def print(self, *args, **kwargs):
        text = str(args[0]) if args else ""
        text = re.sub(r'\[/?.*?\]', '', text)
        print(text)

console = Console() if RICH_AVAILABLE else FallbackConsole()

# ---------------------------------------------------------------------------
# Constants & regex helpers
# ---------------------------------------------------------------------------
DEFAULT_UA = (
    "Mozilla/5.0 (compatible; HiddenEndpointSpider/1.0; +https://example.com)"
)
RANDOM_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
]
JS_URL_RE = re.compile(r"[\"'](?P<url>(?:/[A-Za-z0-9_\-./]+|https?://[^'\"\s]+))[\"']")
JWT_RE = re.compile(r"eyJ[A-Za-z0-9\-_]+?\.eyJ[A-Za-z0-9\-_]+?\.[A-Za-z0-9\-_]+")
API_KEY_RE = re.compile(r"(?i)(api[_-]?key|token|secret)[\"']?\s*[:=]\s*[\"']([a-z0-9-_]{16,})[\"']")
ROBOTS_TXT = "/robots.txt"
SITEMAP_LOC_RE = re.compile(r"<loc>(?P<url>[^<]+)</loc>", re.IGNORECASE)
TIMEOUT = 15

# ---------------------------------------------------------------------------
class CSRFHelper:
    """Retrieve and inject anti‑CSRF tokens where required."""

    def __init__(
        self,
        session,
        token_param: Optional[str],
        url: Optional[str],
        method: str = "GET",
        data: Optional[str] = None,
        retries: int = 0,
        verbose: bool = False,
    ):
        self.sess = session
        self.param = token_param
        self.url = url
        self.method = method.upper()
        self.data = data
        self.retries = retries
        self.verbose = verbose
        self.token_value: Optional[str] = None
        if self.param and self.url:
            self._refresh()

    def _refresh(self):
        if not (self.param and self.url):
            return
        for attempt in range(self.retries + 1):
            try:
                if self.verbose:
                    console.print(f"[*] Fetching CSRF token (attempt {attempt + 1})")
                if self.method == "POST":
                    resp = self.sess.post(self.url, data=self._parse_kv(self.data), timeout=TIMEOUT)
                else:
                    resp = self.sess.get(self.url, params=self._parse_kv(self.data), timeout=TIMEOUT)
                resp.raise_for_status()
            except Exception as exc:
                if self.verbose:
                    console.print(f"❌ [red]CSRF retrieval failed: {exc}[/red]")
                continue
            soup = BeautifulSoup(resp.text, PARSER)
            token_input = soup.find("input", {"name": self.param})
            if token_input and token_input.has_attr("value"):
                self.token_value = token_input["value"]
                if self.verbose:
                    console.print(f"✅ [green]CSRF token obtained: {self.token_value[:10]}…[/green]")
                return
        if self.verbose:
            console.print("❌ [red]CSRF token could not be retrieved after retries[/red]")

    @staticmethod
    def _parse_kv(kv: Optional[str]) -> Mapping[str, str]:
        return {k: v[0] for k, v in parse_qs(kv or "").items()}

    def inject(self, params: MutableMapping[str, str]):
        if self.param and self.token_value:
            params[self.param] = self.token_value

# ---------------------------------------------------------------------------
class EndpointCrawler:
    def __init__(
        self,
        base_url: str,
        method: str = "GET",
        http2: bool = False,
        user_agent: str = DEFAULT_UA,
        random_agent: bool = False,
        proxy: Optional[str] = None,
        verify_ssl: bool = True,
        chunked: bool = False,
        max_depth: int = 2,
        max_workers: int = 10,
        respect_robots: bool = True,
        verbose: bool = False,
        custom_headers: Optional[Dict[str, str]] = None,
        csrf_helper: Optional[CSRFHelper] = None,
        tor: bool = False,
        tor_port: int = 9050,
        tor_type: str = "SOCKS5",
        delay: Optional[float] = None,
        timeout: int = 30,
        retries: int = 3,
        retry_on: Optional[str] = None,
        disable_redirects: bool = False,
        only_crawl_inside: bool = False,
        show_source: bool = False,
        page_size: int = -1,
        include_subdomains: bool = False,
        show_link_source: bool = False,
    ):
        # Scheme enforcement
        if not base_url.startswith(("http://", "https://")):
             base_url = "http://" + base_url
        if base_url.startswith("http://") and verify_ssl:
            base_url = base_url.replace("http://", "https://", 1)
            
        self.base_url = self._norm(base_url)
        parsed_url = urlparse(self.base_url)
        self.origin = parsed_url.netloc
        self.scheme = parsed_url.scheme
        self.base_path = parsed_url.path.rstrip('/') + '/'

        self.method = method.upper()
        self.verbose = verbose
        self.max_depth = max_depth
        self.max_workers = max_workers
        self.csrf = csrf_helper

        ua = random.choice(RANDOM_UAS) if random_agent else user_agent
        headers = {"User-Agent": ua, **(custom_headers or {})}

        self.tor = tor
        self.tor_port = tor_port
        self.tor_type = tor_type
        self.delay = delay
        self.timeout = timeout
        self.retries = retries
        self.retry_on = retry_on
        self.disable_redirects = disable_redirects
        self.only_crawl_inside = only_crawl_inside
        self.show_source = show_source or show_link_source
        self.page_size_kb = page_size
        self.include_subdomains = include_subdomains
        
        self.proxy = f"{self.tor_type.lower()}://127.0.0.1:{self.tor_port}" if self.tor else proxy

        # Initialize session
        if http2 and HTTPX_AVAILABLE:
            self.sess = httpx.Client(
                http2=True, headers=headers, verify=verify_ssl, 
                timeout=self.timeout, proxies=self.proxy, 
                follow_redirects=not self.disable_redirects
            )
        else:
            self.sess = requests.Session()
            self.sess.headers.update(headers)
            self.sess.verify = verify_ssl
            if self.proxy:
                self.sess.proxies = {"http": self.proxy, "https": self.proxy}
            if self.disable_redirects:
                self.sess.max_redirects = 0

        # Storage
        self.to_visit: deque[Tuple[str, int, str]] = deque([(self.base_url, 0, "base")])
        self.seen_urls: Set[str] = {self.base_url}
        self.endpoints: Dict[str, str] = {}
        self.jwt_candidates: Set[str] = set()
        self.api_keys: Set[str] = set()

        self.disallowed: Set[str] = self._fetch_disallowed() if respect_robots else set()
        self.chunked = chunked

    @staticmethod
    def _norm(url: str) -> str:
        u, _ = urldefrag(url)
        return u.rstrip("/") or u

    def _same_site(self, url: str) -> bool:
        parsed = urlparse(url)
        netloc = parsed.netloc.split(':')[0]
        if not netloc: return True # Relative URL
        
        base_netloc = self.origin.split(':')[0]
        if self.include_subdomains:
            return netloc == base_netloc or netloc.endswith(f'.{base_netloc}')
        return netloc == base_netloc

    def _inside_base_path(self, url: str) -> bool:
        if not self.only_crawl_inside: return True
        path = urlparse(url).path
        return path.startswith(self.base_path)

    def _make_request(self, url: str) -> Optional[Tuple[str, str]]:
        params = {}
        if self.csrf: self.csrf.inject(params)
        if self.delay: time.sleep(self.delay)

        for attempt in range(self.retries + 1):
            try:
                if self.verbose: console.print(f"➡️  [dim]Requesting: {url} (attempt {attempt+1})[/dim]")
                
                with self.sess.request(self.method, url, params=params, timeout=self.timeout, stream=True) as resp:
                    resp.raise_for_status()
                    
                    if self.page_size_kb > 0:
                        content_len = int(resp.headers.get('Content-Length', 0))
                        if content_len > self.page_size_kb * 1024:
                            if self.verbose: console.print(f"🚫 [yellow]Skipping {url}, size ({content_len} B) exceeds limit.[/yellow]")
                            return None
                    
                    content_type = resp.headers.get('Content-Type', '').lower()
                    content = resp.text
                    if self.page_size_kb > 0 and len(content) > self.page_size_kb * 1024:
                        if self.verbose: console.print(f"🚫 [yellow]Skipping {url}, downloaded size exceeds limit.[/yellow]")
                        return None
                        
                return content, content_type
            except Exception as exc:
                if self.verbose: console.print(f"❌ [bold red]Request Failed:[/bold red] [red]{url} -> {exc}[/red]")
                if self.retry_on and re.search(self.retry_on, str(exc)):
                    if self.verbose: console.print(f"🔄 [yellow]Retrying due to match on error: {self.retry_on}[/yellow]")
                    continue
        return None

    def _fetch_disallowed(self) -> Set[str]:
        robots_url = urljoin(f"{self.scheme}://{self.origin}", ROBOTS_TXT)
        try:
            resp = self.sess.get(robots_url, timeout=TIMEOUT)
            resp.raise_for_status()
            return {
                self._norm(urljoin(self.base_url, path))
                for line in resp.text.splitlines()
                if line.lower().startswith("disallow:")
                for path in [line.split(":", 1)[1].strip()]
            }
        except Exception:
            return set()

    def _find_links(self, html_text: str, base_url: str) -> Set[str]:
        soup = BeautifulSoup(html_text, PARSER)
        links: Set[str] = set()
        
        tag_attrs = {
            "a": "href", "link": "href", "form": "action",
            "script": "src", "img": "src", "iframe": "src", "source": "src"
        }

        for tag_name, attr_name in tag_attrs.items():
            for tag in soup.find_all(tag_name, **{attr_name: True}):
                url = self._norm(urljoin(base_url, tag[attr_name]))
                if url: links.add(url)
        
        for script in soup.find_all("script"):
            if script.string:
                for match in JS_URL_RE.finditer(script.string):
                    raw_url = html.unescape(match.group("url"))
                    url = self._norm(urljoin(base_url, raw_url))
                    if url: links.add(url)
        return links

    def _extract_secrets(self, text: str):
        self.jwt_candidates.update(JWT_RE.findall(text))
        for _, token in API_KEY_RE.findall(text): self.api_keys.add(token)

    def _parse_sitemap(self) -> Set[str]:
        sitemap_url = urljoin(f"{self.scheme}://{self.origin}", "/sitemap.xml")
        try:
            resp = self.sess.get(sitemap_url, timeout=TIMEOUT)
            resp.raise_for_status()
            return {
                self._norm(m.group("url"))
                for m in SITEMAP_LOC_RE.finditer(resp.text)
                if self._same_site(self._norm(m.group("url"))) and self._inside_base_path(self._norm(m.group("url")))
            }
        except Exception:
            return set()

    def crawl(self):
        for url in self._parse_sitemap():
            if url not in self.seen_urls:
                self.seen_urls.add(url)
                self.to_visit.append((url, 1, "sitemap"))

        from concurrent.futures import ThreadPoolExecutor, as_completed
        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {}
            while self.to_visit or futures:
                while self.to_visit and len(futures) < self.max_workers:
                    url, depth, source = self.to_visit.popleft()
                    
                    if depth > self.max_depth: continue
                    if url in self.disallowed:
                        if self.verbose: console.print(f"🚫 [yellow]Skipping disallowed URL: {url}[/yellow]")
                        continue
                    
                    if self.verbose: console.print(f"🕸️  [bold blue]Crawling (Depth: {depth}, Source: {source.split('?')[0]}):[/bold blue] {url.split('?')[0]}")
                    future = pool.submit(self._make_request, url)
                    futures[future] = (url, depth)
                
                if not futures: break
                
                for future in as_completed(futures):
                    url, depth = futures.pop(future)
                    result = future.result()
                    if not result: continue
                        
                    page_content, content_type = result
                    self._extract_secrets(page_content)
                    if url != self.base_url: self.endpoints[url] = source
                    
                    # Only parse content if it's HTML to avoid warnings and errors
                    if 'html' in content_type:
                        new_links = self._find_links(page_content, url)
                        for link in new_links:
                            if link in self.seen_urls:
                                continue

                            if (self._same_site(link) and 
                                self._inside_base_path(link) and 
                                link not in self.disallowed and 
                                (depth + 1) <= self.max_depth):
                                
                                self.seen_urls.add(link)
                                self.to_visit.append((link, depth + 1, url))

    def result_dict(self):
        endpoints_list = [{"endpoint": k, "source": v} for k, v in self.endpoints.items()]
        return {
            "endpoints": sorted(endpoints_list, key=lambda x: x['endpoint']),
            "jwt_candidates": sorted(list(self.jwt_candidates)),
            "api_keys": sorted(list(self.api_keys)),
        }

# ---------------------------------------------------------------------------
# CLI and Main (No changes below this line except for installation prompts)
# ---------------------------------------------------------------------------

def parse_headers(header_str: Optional[str]) -> Dict[str, str]:
    if not header_str: return {}
    return {k.strip(): v.strip() for seg in header_str.split(";;") if ":" in seg for k, v in [seg.split(":", 1)]}

def load_raw_request(path: Path) -> Tuple[str, str, Dict[str, str]]:
    try:
        lines = path.read_text().splitlines()
        if not lines: raise ValueError("Empty request file")
        method, target, _ = lines[0].split()
        host = ""
        hdrs = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                key, value = k.strip(), v.strip()
                hdrs[key] = value
                if key.lower() == "host": host = value
        
        scheme = "https" if "https" in target or hdrs.get('Referer', '').startswith('https') else "http"
        url = target if target.startswith("http") else f"{scheme}://{host}{target}"
        return url, method, hdrs
    except Exception as e:
        console.print(f"🔥 [bold red]CRITICAL ERROR[/bold red] parsing request file: {e}")
        sys.exit(1)

def build_arg_parser() -> argparse.ArgumentParser:
    os.system("cls" if os.name == "nt" else "clear")
    console.print(banner)
    p = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter, description="[*] Discover hidden endpoints on a website.")
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("url", nargs="?", help="Single target URL (e.g. https://example.com)")
    src.add_argument("-m", "--bulkfile", type=Path, help="File with multiple target URLs (one per line)")
    src.add_argument("-r", "--requestfile", type=Path, help="Load raw HTTP request from file")

    p.add_argument("--method", default="GET", help="HTTP method to use (GET, POST, etc.)")
    p.add_argument("--http2", action="store_true", help="Use HTTP/2 (requires httpx)")
    p.add_argument("--random-agent", action="store_true", help="Pick a random User-Agent header")
    p.add_argument("-A", "--user-agent", help="Custom User-Agent header value")
    p.add_argument("-H", "--header", help="Extra headers separated by ';;'")
    p.add_argument("--proxy", help="Proxy URL (e.g. http://127.0.0.1:8080)")
    p.add_argument("--insecure", action="store_true", help="Disable SSL verification")
    p.add_argument("--chunked", action="store_true", help="Use chunked transfer encoding (Note: handled automatically by libs)")
    p.add_argument("--depth", type=int, default=2, help="Maximum crawl depth")
    p.add_argument("-t", "--threads", type=int, default=10, help="Concurrent worker threads")
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    p.add_argument("--no-robots", dest="respect_robots", action="store_false", help="Ignore robots.txt disallow rules")

    p.add_argument("--tor", action="store_true", help="Use Tor anonymity network")
    p.add_argument("--tor-port", type=int, default=9050, help="Set Tor proxy port")
    p.add_argument("--tor-type", choices=["HTTP", "SOCKS4", "SOCKS5"], default="SOCKS5", help="Set Tor proxy type")
    p.add_argument("--check-tor", action="store_true", help="Check if Tor is used properly")
    p.add_argument("--delay", type=float, help="Delay in seconds between each HTTP request")
    p.add_argument("--timeout", type=int, default=30, help="Seconds to wait before connection timeout")
    p.add_argument("--retries", type=int, default=3, help="Retries when a connection timeouts")
    p.add_argument("--retry-on", help="Retry request on regexp matching content (e.g. 'captcha')")
    p.add_argument("-dr", "--disable-redirects", action="store_true", help="Disable following HTTP redirects")
    p.add_argument("-i", "--only-crawl-inside", action="store_true", help="Only crawl URLs within the initial path")
    p.add_argument("-s", "--show-source", action="store_true", help="Show the source of a URL (alias for -w)")
    p.add_argument("-size", "--page-size", type=int, default=-1, help="Page size limit in KB. (default: -1, no limit)")
    p.add_argument("-subs", "--include-subdomains", action="store_true", help="Include subdomains for crawling")
    p.add_argument("-u", "--unique-urls", action="store_true", help="Show only unique URLs across all targets")
    p.add_argument("-w", "--show-link-source", action="store_true", help="Show at which link the URL is found")

    csrf = p.add_argument_group("CSRF Options")
    csrf.add_argument("--csrf-token", help="Form/query parameter name that holds anti‑CSRF token")
    csrf.add_argument("--csrf-url", help="URL to fetch anti‑CSRF token from")
    csrf.add_argument("--csrf-method", default="GET", help="HTTP method for anti‑CSRF token fetch")
    csrf.add_argument("--csrf-data", help="POST data for anti‑CSRF token fetch")
    csrf.add_argument("--csrf-retries", type=int, default=0, help="Retries for anti‑CSRF token fetch")

    out = p.add_argument_group("Output Options")
    out.add_argument("-o", "--output", type=Path, help="JSON output file for all findings")
    out.add_argument("--csv", type=Path, help="Optional CSV output of endpoints only")
    return p

def main(argv: Optional[Iterable[str]] = None):
    if not RICH_AVAILABLE:
        console.print("[!] Warning: 'rich' library not found. Falling back to plain text output.")
        console.print("[!] For a better experience, run: pip install rich")
    if PARSER != "lxml":
         console.print("[!] Warning: 'lxml' library not found. Falling back to the slower 'html.parser'.")
         console.print("[!] For a faster crawl, run: pip install lxml")

    args = build_arg_parser().parse_args(argv)

    targets: List[Tuple[str, Dict[str, str], str]] = []
    if args.requestfile:
        url, method, hdrs = load_raw_request(args.requestfile)
        targets.append((url, hdrs, method))
    elif args.bulkfile:
        targets.extend((line.strip(), {}, args.method) for line in args.bulkfile.read_text().splitlines() if line.strip())
    else:
        targets.append((args.url, {}, args.method))

    extra_headers = parse_headers(args.header)
    all_findings: List[dict] = []
    last_proxy = None

    for target_url, raw_hdrs, method in targets:
        console.print(f"\n🎯 [bold magenta]Target:[/] [bold]{target_url}[/]")
        csrf_session = requests.Session()
        if args.proxy: csrf_session.proxies = {"http": args.proxy, "https": args.proxy}
        csrf_session.verify = not args.insecure

        csrf = CSRFHelper(
            session=csrf_session, token_param=args.csrf_token, url=args.csrf_url,
            method=args.csrf_method, data=args.csrf_data, retries=args.csrf_retries,
            verbose=args.verbose,
        ) if args.csrf_token and args.csrf_url else None

        try:
            crawler = EndpointCrawler(
                base_url=target_url, method=method, http2=args.http2,
                user_agent=args.user_agent or DEFAULT_UA, random_agent=args.random_agent,
                proxy=args.proxy, verify_ssl=not args.insecure, chunked=args.chunked,
                max_depth=args.depth, max_workers=args.threads,
                respect_robots=args.respect_robots, verbose=args.verbose,
                custom_headers={**raw_hdrs, **extra_headers}, csrf_helper=csrf,
                tor=args.tor, tor_port=args.tor_port, tor_type=args.tor_type,
                delay=args.delay, timeout=args.timeout, retries=args.retries,
                retry_on=args.retry_on, disable_redirects=args.disable_redirects,
                only_crawl_inside=args.only_crawl_inside, show_source=args.show_source,
                page_size=args.page_size, include_subdomains=args.include_subdomains,
                show_link_source=args.show_link_source,
            )
            last_proxy = crawler.proxy
            crawler.crawl()
            findings = crawler.result_dict()
            findings["target"] = target_url
            all_findings.append(findings)
            console.print(f"🎉 [bold green]Crawl Finished.[/] Found {len(findings['endpoints'])} endpoints.")
        except Exception as e:
            console.print(f"🔥 [bold red]CRITICAL ERROR[/bold red] while crawling {target_url}: {e}")
            continue

    if args.check_tor and last_proxy:
        console.print("\n🧅 [bold yellow]Checking Tor Connection...[/bold yellow]")
        try:
            resp = requests.get("https://check.torproject.org/api/ip", proxies={"http": last_proxy, "https": last_proxy}, timeout=10)
            test_data = resp.json()
            if test_data.get("IsTor"):
                console.print(f"✅ [green]Tor check successful. IP: {test_data.get('IP')}[/green]")
            else:
                console.print(f"⚠️  [bold red]Tor check FAILED. You are NOT connected through Tor. IP: {test_data.get('IP')}[/bold red]")
        except Exception as e:
            console.print(f"❌ [red]Tor check request failed: {e}[/red]")

    if args.output:
        try:
            with args.output.open("w") as f: json.dump(all_findings, f, indent=2)
            console.print(f"\n💾 [green]JSON results saved to {args.output}[/green]")
        except Exception as e: console.print(f"❌ [red]Error writing JSON output: {e}[/red]")

    if args.csv:
        try:
            all_endpoints = [ep for f in all_findings for ep in f.get("endpoints", [])]
            with args.csv.open("w", newline="") as f:
                writer = csv.writer(f)
                if all_endpoints and isinstance(all_endpoints[0], dict):
                    writer.writerow(["Endpoint", "Source"])
                    unique_eps = {ep['endpoint']: ep['source'] for ep in all_endpoints}
                    writer.writerows([[k, v] for k, v in sorted(unique_eps.items())])
                else:
                    writer.writerow(["Endpoint"])
                    writer.writerows([[u] for u in sorted(list(set(all_endpoints)))])
            console.print(f"💾 [green]CSV results saved to {args.csv}[/green]")
        except Exception as e: console.print(f"❌ [red]Error writing CSV output: {e}[/red]")

    if not args.output and not args.csv:
        console.print("\n", Panel("✨ Discovered Endpoints ✨", expand=False, border_style="cyan"))
        unique_printed_global = set()
        for f in all_findings:
            target_panel = Panel(f"[bold magenta]{f['target']}[/]", expand=False, border_style="magenta", title="🎯 Target")
            console.print(target_panel)

            endpoints_to_show = []
            for item in f["endpoints"]:
                if args.unique_urls and item['endpoint'] in unique_printed_global:
                    continue
                endpoints_to_show.append(item)
                unique_printed_global.add(item['endpoint'])

            if not endpoints_to_show:
                console.print("🤷 [yellow]No new endpoints found for this target.[/yellow]\n")
                continue

            table = Table(show_header=True, header_style="bold blue", box=None)
            table.add_column("🔗 Endpoint:", style="cyan", no_wrap=False)
            if args.show_link_source or args.show_source:
                table.add_column("📍 Discovered From:", style="dim", no_wrap=False)

            for item in endpoints_to_show:
                if args.show_link_source or args.show_source:
                    table.add_row(item['endpoint'], item['source'])
                else:
                    table.add_row(item['endpoint'])
            
            console.print(table)
            console.print()


if __name__ == "__main__":
    main()
