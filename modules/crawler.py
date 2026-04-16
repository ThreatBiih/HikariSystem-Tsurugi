# HikariSystem Tsurugi/modules/crawler.py
"""
HEADLESS-FIRST CRAWLER - Full DOM Rendering with Playwright
Fallback to curl_cffi for --fast mode.

Features:
- DEFAULT: Playwright (full JS rendering, SPA support)
- FAST MODE: curl_cffi (TLS stealth, no JS)
- Network interception for API discovery
- DOM sink detection for DOM XSS
- JSA (JavaScript Analysis) for secrets
- URL deduplication by normalized path pattern
- Priority queue: param-carrying URLs crawled before static pages
"""
import re
import asyncio
import time
from urllib.parse import urljoin, urlparse, urlunparse, parse_qs, urlencode
from typing import Dict, List, Set, Tuple
from bs4 import BeautifulSoup
from dataclasses import dataclass, field
from core.ui import console, log_info, log_success, log_warning, log_error
from core.requester import TsurugiSession

# Check headless availability
_HEADLESS_AVAILABLE = False
try:
    from core.headless import HeadlessEngine, HeadlessResult, is_headless_available
    _HEADLESS_AVAILABLE = is_headless_available()
except ImportError:
    pass


# ═══════════════════════════════════════════════════════════════════════════════
#  URL NORMALIZATION & DEDUPLICATION
# ═══════════════════════════════════════════════════════════════════════════════

# Param value placeholder for dedup — /item?id=1 and /item?id=2 become the same pattern.
_PARAM_PLACEHOLDER = "__V__"

def _normalize_url(url: str) -> str:
    """
    Normalize a URL for dedup: lowercase scheme+host, strip fragment,
    sort query params, and replace param VALUES with a placeholder so
    /page?id=1 and /page?id=99 collapse into one path pattern.
    """
    p = urlparse(url)
    qs = parse_qs(p.query, keep_blank_values=True)
    # Replace each value list with the placeholder.
    normalized_qs = {k: [_PARAM_PLACEHOLDER] for k in sorted(qs.keys())}
    query = urlencode(normalized_qs, doseq=True) if normalized_qs else ""
    return urlunparse((
        p.scheme.lower(), p.netloc.lower(), p.path.rstrip("/") or "/",
        "", query, "",
    ))


def _has_params(url: str) -> bool:
    return "=" in urlparse(url).query


# Minimum delay between requests (seconds) — gentle enough for prod sites.
_CRAWL_DELAY = 0.3


# ═══════════════════════════════════════════════════════════════════════════════
#  PATTERNS
# ═══════════════════════════════════════════════════════════════════════════════

JS_ENDPOINT_REGEX = r"[\"']((/[a-zA-Z0-9_?&=/\-\.]+|https?://[a-zA-Z0-9_?&=/\-\.]+))[\"']"

JSA_PATTERNS = {
    "API Key": r"(?i)api_key\s*[:=]\s*['\"][\w\-]{32,}['\"]",
    "AWS Key": r"(?i)aws_access_key_id\s*[:=]\s*['\"]AKIA[\w]{16}['\"]",
    "Endpoint": r"(?i)['\"]/api/v\d/[\w\-/]+['\"]",
    "Hidden Paths": r"(?i)['\"]/admin/[\w\-/]+['\"]"
}

API_PATTERNS = [
    r'["\']?(/api/[a-zA-Z0-9_\-/\.]+)["\']?',
    r'["\']?(/v\d+/[a-zA-Z0-9_\-/\.]+)["\']?',
    r'["\']?(/graphql)["\']?',
    r'["\']?(/rest/[a-zA-Z0-9_\-/\.]+)["\']?',
    r'["\']?(/ajax/[a-zA-Z0-9_\-/\.]+)["\']?',
    r'fetch\s*\(\s*["\']([^"\']+)["\']',
    r'axios\.[a-z]+\s*\(\s*["\']([^"\']+)["\']',
    r'\$\.ajax\s*\(\s*\{[^}]*url\s*:\s*["\']([^"\']+)["\']',
]

API_SUBDOMAINS = [
    "api", "backend", "rest", "graphql", "ws", "socket", 
    "v1", "v2", "v3", "gateway", "services", "data"
]


# ═══════════════════════════════════════════════════════════════════════════════
#  RESULT DATACLASS
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class CrawlResult:
    """Complete crawl result."""
    get_endpoints: List[str] = field(default_factory=list)
    post_forms: List[Tuple[str, List[str]]] = field(default_factory=list)
    api_endpoints: List[str] = field(default_factory=list)
    js_files: List[str] = field(default_factory=list)
    jsa_secrets: List[str] = field(default_factory=list)
    dom_sinks: List[Dict] = field(default_factory=list)
    pages_crawled: int = 0
    mode: str = "headless"


# ═══════════════════════════════════════════════════════════════════════════════
#  EXTRACTION FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

def extract_js_endpoints(js_content: str) -> Set[str]:
    """Extract endpoints from JS content."""
    endpoints = set()
    matches = re.finditer(JS_ENDPOINT_REGEX, js_content)
    
    for match in matches:
        path = match.group(1)
        if len(path) > 4 and not path.endswith(('.png', '.svg', '.css', '.js')):
            if "/" in path:
                endpoints.add(path)
    return endpoints


def extract_api_endpoints(content: str) -> Set[str]:
    """Extract API endpoints from content."""
    endpoints = set()
    
    for pattern in API_PATTERNS:
        matches = re.findall(pattern, content, re.IGNORECASE)
        for match in matches:
            if isinstance(match, tuple):
                match = match[0]
            match = match.strip()
            if match and len(match) > 3 and not match.endswith(('.js', '.css', '.png')):
                endpoints.add(match)
    
    return endpoints


def scan_js_secrets(content: str) -> List[str]:
    """Scan JS content for secrets."""
    findings = []
    for name, pattern in JSA_PATTERNS.items():
        matches = re.findall(pattern, content)
        for match in matches:
            findings.append(f"{name}: {match}")
    return findings


# ═══════════════════════════════════════════════════════════════════════════════
#  HEADLESS CRAWLER (DEFAULT)
# ═══════════════════════════════════════════════════════════════════════════════

async def crawl_headless(start_url: str, depth: int = 2,
                         cookie: str = None, proxy: str = None) -> CrawlResult:
    """
    Crawl using Playwright with full JS rendering.
    DEFAULT MODE for SPA/React/Vue/Angular sites.
    Deduplicates by normalized URL pattern.
    """
    result = CrawlResult(mode="headless")

    seen_patterns: Set[str] = set()
    scanned_js: Set[str] = set()
    to_visit: List[Tuple[int, str, int]] = [(0 if _has_params(start_url) else 1, start_url, 0)]
    domain = urlparse(start_url).netloc
    base = f"{urlparse(start_url).scheme}://{domain}"

    async with HeadlessEngine(cookie_string=cookie, proxy=proxy) as engine:
        while to_visit:
            to_visit.sort(key=lambda x: (x[2], x[0]))
            _, url, current_depth = to_visit.pop(0)

            norm = _normalize_url(url)
            if norm in seen_patterns or current_depth > depth:
                continue
            if urlparse(url).netloc != domain:
                continue

            seen_patterns.add(norm)
            result.pages_crawled += 1
            console.print(f"  [cyan]Crawling (headless):[/cyan] {url}", style="dim")

            await asyncio.sleep(_CRAWL_DELAY)

            try:
                page_result = await engine.get(url, auto_scroll=True, detect_sinks=True)
                if page_result.error:
                    continue

                if _has_params(url):
                    result.get_endpoints.append(url)
                    log_success(f"Found GET endpoint: {url}")

                for api in page_result.api_endpoints:
                    if api not in result.api_endpoints:
                        result.api_endpoints.append(api)
                        console.print(f"    [magenta]-> API:[/magenta] {api[:80]}")

                for js in page_result.js_files:
                    if js not in result.js_files:
                        result.js_files.append(js)

                if page_result.dom_sinks:
                    for sink in page_result.dom_sinks:
                        console.print(f"    [yellow][!] DOM Sink:[/yellow] {sink.get('type')} in {sink.get('element', 'unknown')}")
                        result.dom_sinks.append(sink)

                soup = BeautifulSoup(page_result.html, 'html.parser')

                for form in soup.find_all('form'):
                    action = form.get('action') or url
                    action_url = urljoin(url, action)
                    method = form.get('method', 'get').lower()
                    inputs = [i.get('name') for i in form.find_all('input') if i.get('name')]
                    if inputs and method == 'post':
                        result.post_forms.append((action_url, inputs))
                        console.print(f"    [yellow]POST Form:[/yellow] {action_url}")

                if current_depth < depth:
                    for link in soup.find_all('a', href=True):
                        href = link.get('href')
                        abs_link = urljoin(url, href)
                        if abs_link.startswith(('javascript:', '#', 'mailto:')):
                            continue
                        link_norm = _normalize_url(abs_link)
                        if link_norm not in seen_patterns:
                            prio = 0 if _has_params(abs_link) else 1
                            to_visit.append((prio, abs_link, current_depth + 1))

            except Exception as e:
                log_warning(f"Error crawling {url}: {e}")

    return result


# ═══════════════════════════════════════════════════════════════════════════════
#  FAST CRAWLER (curl_cffi)
# ═══════════════════════════════════════════════════════════════════════════════

def crawl_fast(start_url: str, depth: int = 2,
               cookie: str = None, proxy: str = None) -> CrawlResult:
    """
    Fast crawl using curl_cffi (no JS rendering).
    FAST MODE for static sites or when speed is priority.
    Includes URL dedup by normalized pattern and rate-limiting.
    """
    result = CrawlResult(mode="fast")

    requester = TsurugiSession(cookie_string=cookie, proxy=proxy)
    seen_patterns: Set[str] = set()
    scanned_js: Set[str] = set()
    # Priority queue: URLs with params go first (lower number = higher priority).
    to_visit: List[Tuple[int, str, int]] = [(0 if _has_params(start_url) else 1, start_url, 0)]
    domain = urlparse(start_url).netloc
    base = f"{urlparse(start_url).scheme}://{domain}"

    while to_visit:
        to_visit.sort(key=lambda x: (x[2], x[0]))  # depth first, then priority
        _, url, current_depth = to_visit.pop(0)

        norm = _normalize_url(url)
        if norm in seen_patterns or current_depth > depth:
            continue
        if urlparse(url).netloc != domain:
            continue

        seen_patterns.add(norm)
        result.pages_crawled += 1
        console.print(f"  [cyan]Crawling (fast):[/cyan] {url}", style="dim")

        time.sleep(_CRAWL_DELAY)

        try:
            resp = requester.get(url)
            if not resp or resp.status_code != 200:
                continue

            if _has_params(url):
                result.get_endpoints.append(url)

            soup = BeautifulSoup(resp.text, 'html.parser')

            for form in soup.find_all('form'):
                action = form.get('action') or url
                action_url = urljoin(url, action)
                method = form.get('method', 'get').lower()
                inputs = [i.get('name') for i in form.find_all('input') if i.get('name')]
                if inputs and method == 'post':
                    result.post_forms.append((action_url, inputs))

            for script in soup.find_all('script', src=True):
                src = script.get('src')
                if src:
                    js_url = urljoin(url, src)
                    if js_url in scanned_js:
                        continue
                    scanned_js.add(js_url)

                    if domain in js_url and "jquery" not in js_url:
                        try:
                            js_resp = requester.get(js_url)
                            if js_resp:
                                result.js_files.append(js_url)
                                for ep in extract_api_endpoints(js_resp.text):
                                    if ep.startswith("/"):
                                        result.api_endpoints.append(urljoin(base, ep))
                                    elif ep.startswith("http"):
                                        result.api_endpoints.append(ep)
                                for secret in scan_js_secrets(js_resp.text):
                                    result.jsa_secrets.append(secret)
                                    console.print(f"    [red][!] Secret:[/red] {secret}")
                        except Exception:
                            pass

            if current_depth < depth:
                for link in soup.find_all('a', href=True):
                    href = link.get('href')
                    abs_link = urljoin(url, href)
                    if abs_link.startswith(('javascript:', '#', 'mailto:')):
                        continue
                    link_norm = _normalize_url(abs_link)
                    if link_norm not in seen_patterns:
                        prio = 0 if _has_params(abs_link) else 1
                        to_visit.append((prio, abs_link, current_depth + 1))

        except Exception:
            pass

    return result


# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

def crawl_target(start_url: str, depth: int = 2, cookie: str = None, 
                 proxy: str = None, fast: bool = False) -> Dict:
    """
    Main crawler entry point.
    
    Args:
        start_url: Target URL
        depth: Crawl depth
        cookie: Session cookie
        proxy: Proxy URL
        fast: Use fast mode (curl_cffi, no JS) instead of headless
        
    Returns:
        Dict with crawl results
    """
    # Determine mode
    use_headless = _HEADLESS_AVAILABLE and not fast
    
    if not use_headless and not fast:
        log_warning("Playwright not available. Falling back to fast mode (no JS rendering).")
        log_warning("Install with: pip install playwright playwright-stealth && playwright install chromium")
    
    mode_str = "HEADLESS (Playwright)" if use_headless else "FAST (curl_cffi)"
    console.print(f"\n[bold magenta][*] TSURUGI CRAWLER[/bold magenta] -> [yellow]{start_url}[/yellow]")
    console.print(f"[bold cyan][*] Mode: {mode_str} | Depth: {depth}[/bold cyan]")
    
    # Execute crawl
    if use_headless:
        result = asyncio.run(crawl_headless(start_url, depth, cookie, proxy))
    else:
        result = crawl_fast(start_url, depth, cookie, proxy)
    
    # Display results
    console.print(f"\n[bold green][+] Crawl Complete![/bold green]")
    console.print(f"  Pages crawled: {result.pages_crawled}")
    console.print(f"  GET endpoints: {len(result.get_endpoints)}")
    console.print(f"  POST forms: {len(result.post_forms)}")
    console.print(f"  API endpoints: {len(result.api_endpoints)}")
    console.print(f"  JS files: {len(result.js_files)}")
    
    if result.dom_sinks:
        console.print(f"  [yellow]DOM Sinks (XSS vectors): {len(result.dom_sinks)}[/yellow]")
    
    if result.jsa_secrets:
        console.print(f"  [red]Secrets found: {len(result.jsa_secrets)}[/red]")
    
    # Show API endpoints
    if result.api_endpoints:
        console.print(f"\n[bold cyan][*] Discovered APIs:[/bold cyan]")
        for api in result.api_endpoints[:15]:
            console.print(f"  - {api}")
        if len(result.api_endpoints) > 15:
            console.print(f"  ...and {len(result.api_endpoints) - 15} more")
    
    return {
        "get": result.get_endpoints,
        "post": result.post_forms,
        "api": result.api_endpoints,
        "js": result.js_files,
        "dom_sinks": result.dom_sinks,
        "secrets": result.jsa_secrets,
        "mode": result.mode,
        "pages": result.pages_crawled
    }


def discover_api_endpoints(base_url: str, cookie: str = None, 
                           proxy: str = None, fast: bool = False) -> Dict:
    """
    Specialized API endpoint discovery (compatibility wrapper).
    """
    console.print(f"\n[bold magenta][*] API ENDPOINT DISCOVERY[/bold magenta] -> [yellow]{base_url}[/yellow]")
    
    result = crawl_target(base_url, depth=1, cookie=cookie, proxy=proxy, fast=fast)
    
    # Also test common API paths
    requester = TsurugiSession(cookie_string=cookie, proxy=proxy)
    parsed = urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    
    api_endpoints = set(result.get("api", []))
    
    common_paths = [
        "/api", "/api/v1", "/api/v2", "/graphql", 
        "/swagger.json", "/openapi.json", "/api-docs"
    ]
    
    for path in common_paths:
        test_url = urljoin(base, path)
        try:
            resp = requester.get(test_url, timeout=5)
            # Only 200 (open) and 401 (exists, needs auth) are real API signals.
            # 301/302/403 are noise (redirect to login, generic deny).
            if resp and resp.status_code in [200, 401]:
                api_endpoints.add(test_url)
                console.print(f"  [green][+][/green] {path} ({resp.status_code})")
        except Exception:
            pass
    
    return {
        "endpoints": list(api_endpoints),
        "total": len(api_endpoints)
    }