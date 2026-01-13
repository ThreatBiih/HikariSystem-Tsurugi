# HikariSystem Tsurugi/core/cloudbuster.py
"""
CLOUDBUSTER MODULE - Multi-layer Cloudflare bypass system
Layers:
  1. cloudscraper - JS challenge solver (lightweight)
  2. playwright + stealth patches - Full browser emulation
  3. undetected-chromedriver - Fallback (optional, requires Chrome)
"""
import time
from typing import Optional, Dict, Any
from urllib.parse import urlparse
from core.ui import console, log_info, log_warning, log_success, log_error
from core.stealth import detect_cloudflare, StealthEngine, StealthConfig

# Try importing optional dependencies
CLOUDSCRAPER_AVAILABLE = False
PLAYWRIGHT_STEALTH_AVAILABLE = False

try:
    import cloudscraper
    CLOUDSCRAPER_AVAILABLE = True
except ImportError:
    pass

try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_STEALTH_AVAILABLE = True
except ImportError:
    pass


class MockResponse:
    """Mock response object compatible with requests.Response interface."""
    def __init__(self, text: str, status_code: int, headers: Dict = None, url: str = ""):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {}
        self.url = url
        self.content = text.encode() if isinstance(text, str) else text
    
    def json(self):
        import json
        return json.loads(self.text)


class CloudBuster:
    """
    Multi-layer Cloudflare bypass engine.
    Automatically escalates through bypass layers if needed.
    """
    
    def __init__(
        self,
        proxy: str = None,
        cookie_string: str = None,
        stealth_config: StealthConfig = None,
        auto_escalate: bool = True,
        verbose: bool = False
    ):
        self.proxy = proxy
        self.cookies = self._parse_cookies(cookie_string)
        self.stealth = StealthEngine(stealth_config or StealthConfig(enabled=True))
        self.auto_escalate = auto_escalate
        self.verbose = verbose
        
        # State
        self._scraper = None
        self._playwright = None
        self._browser = None
        self._context = None
        self._solved_domains = {}  # domain -> cookies from solved challenges
        
        # Layer tracking
        self.current_layer = 0
        self.layer_names = ["cloudscraper", "playwright-stealth", "undetected-chrome"]
    
    def _parse_cookies(self, cookie_string: str) -> Dict[str, str]:
        """Parse cookie string into dict."""
        cookies = {}
        if cookie_string:
            try:
                for chunk in cookie_string.split(";"):
                    if "=" in chunk:
                        k, v = chunk.split("=", 1)
                        cookies[k.strip()] = v.strip()
            except Exception:
                pass
        return cookies
    
    def _log(self, msg: str, level: str = "info"):
        """Log message if verbose mode enabled."""
        if self.verbose:
            if level == "info":
                log_info(f"[CloudBuster] {msg}")
            elif level == "warning":
                log_warning(f"[CloudBuster] {msg}")
            elif level == "success":
                log_success(f"[CloudBuster] {msg}")
            elif level == "error":
                log_error(f"[CloudBuster] {msg}")
    
    def _get_scraper(self):
        """Get or create cloudscraper instance."""
        if not CLOUDSCRAPER_AVAILABLE:
            return None
        
        if self._scraper is None:
            try:
                self._scraper = cloudscraper.create_scraper(
                    browser={
                        'browser': 'chrome',
                        'platform': 'windows',
                        'desktop': True
                    },
                    delay=5
                )
                
                # Set proxy if available
                if self.proxy:
                    self._scraper.proxies = {
                        "http": self.proxy,
                        "https": self.proxy
                    }
                
                # Set cookies
                for k, v in self.cookies.items():
                    self._scraper.cookies.set(k, v)
                    
            except Exception as e:
                self._log(f"Failed to create cloudscraper: {e}", "error")
                return None
        
        return self._scraper
    
    def _init_playwright(self):
        """Initialize Playwright with stealth settings."""
        if not PLAYWRIGHT_STEALTH_AVAILABLE:
            return False
        
        if self._browser is not None:
            return True
        
        try:
            self._playwright = sync_playwright().start()
            
            # Launch with stealth args
            launch_args = [
                "--no-sandbox",
                "--disable-blink-features=AutomationControlled",
                "--disable-infobars",
                "--disable-dev-shm-usage",
                "--disable-gpu",
            ]
            
            browser_kwargs = {
                "headless": True,
                "args": launch_args,
            }
            
            if self.proxy:
                browser_kwargs["proxy"] = {"server": self.proxy}
            
            self._browser = self._playwright.chromium.launch(**browser_kwargs)
            
            # Create context with stealth headers
            headers = self.stealth.get_stealth_headers()
            context_kwargs = {
                "user_agent": headers.get("User-Agent"),
                "ignore_https_errors": True,
                "extra_http_headers": {
                    k: v for k, v in headers.items() 
                    if k != "User-Agent"
                }
            }
            
            self._context = self._browser.new_context(**context_kwargs)
            
            # Add stealth scripts
            self._context.add_init_script("""
                // Remove webdriver property
                Object.defineProperty(navigator, 'webdriver', {
                    get: () => undefined
                });
                
                // Fix chrome object
                window.chrome = {
                    runtime: {}
                };
                
                // Fix permissions
                const originalQuery = window.navigator.permissions.query;
                window.navigator.permissions.query = (parameters) => (
                    parameters.name === 'notifications' ?
                        Promise.resolve({ state: Notification.permission }) :
                        originalQuery(parameters)
                );
                
                // Fix plugins
                Object.defineProperty(navigator, 'plugins', {
                    get: () => [1, 2, 3, 4, 5]
                });
                
                // Fix languages
                Object.defineProperty(navigator, 'languages', {
                    get: () => ['en-US', 'en']
                });
            """)
            
            # Set cookies
            if self.cookies:
                cookie_list = []
                for k, v in self.cookies.items():
                    cookie_list.append({
                        "name": k,
                        "value": v,
                        "domain": "",  # Will be set per-request
                        "path": "/"
                    })
                # Cookies will be set per-domain during request
            
            self._log("Playwright initialized with stealth patches", "success")
            return True
            
        except Exception as e:
            self._log(f"Failed to initialize Playwright: {e}", "error")
            return False
    
    def _make_playwright_request(self, url: str, method: str = "GET", data: Dict = None) -> Optional[MockResponse]:
        """Make request using Playwright."""
        if not self._init_playwright():
            return None
        
        try:
            page = self._context.new_page()
            
            # Set cookies for this domain
            domain = urlparse(url).netloc
            if self.cookies:
                cookie_list = [{
                    "name": k, "value": v, "domain": domain, "path": "/"
                } for k, v in self.cookies.items()]
                self._context.add_cookies(cookie_list)
            
            # Add solved challenge cookies if available
            if domain in self._solved_domains:
                self._context.add_cookies(self._solved_domains[domain])
            
            # Navigate
            try:
                response = page.goto(url, timeout=30000, wait_until="networkidle")
            except Exception:
                # Fallback to domcontentloaded
                response = page.goto(url, timeout=30000, wait_until="domcontentloaded")
            
            # Wait a bit for any dynamic content
            page.wait_for_timeout(1000)
            
            content = page.content()
            status = response.status if response else 200
            headers = {k: v for k, v in (response.headers.items() if response else [])}
            
            # Check if this was a CF challenge that got solved
            is_cf, cf_type = detect_cloudflare(headers, content)
            if not is_cf and cf_type != "cf_cdn_only":
                # Store cookies for this domain
                cookies = self._context.cookies()
                self._solved_domains[domain] = [c for c in cookies if domain in c.get("domain", "")]
                self._log(f"Challenge solved for {domain}, cookies stored", "success")
            
            page.close()
            return MockResponse(content, status, headers, url)
            
        except Exception as e:
            self._log(f"Playwright request failed: {e}", "error")
            return None
    
    def request(
        self,
        url: str,
        method: str = "GET",
        params: Dict = None,
        data: Dict = None,
        headers: Dict = None,
        timeout: int = 10
    ) -> Optional[MockResponse]:
        """
        Make request with automatic Cloudflare bypass.
        Escalates through layers if needed.
        """
        # Build URL with params
        if params:
            from urllib.parse import urlencode
            sep = "&" if "?" in url else "?"
            url = url + sep + urlencode(params)
        
        # Try Layer 1: cloudscraper
        if self.current_layer == 0:
            response = self._try_cloudscraper(url, method, data, headers, timeout)
            if response:
                is_cf, cf_type = detect_cloudflare(dict(response.headers), response.text)
                if not is_cf or cf_type == "cf_cdn_only":
                    return response
                elif self.auto_escalate:
                    self._log("Cloudflare challenge detected, escalating to Playwright", "warning")
                    self.current_layer = 1
                else:
                    return response  # Return blocked response if not auto-escalating
        
        # Try Layer 2: Playwright with stealth
        if self.current_layer <= 1:
            response = self._make_playwright_request(url, method, data)
            if response:
                is_cf, cf_type = detect_cloudflare(response.headers, response.text)
                if not is_cf or cf_type == "cf_cdn_only":
                    return response
                elif self.auto_escalate:
                    self._log("Playwright failed to bypass, returning blocked response", "warning")
                    self.current_layer = 2
        
        # Layer 3 would be undetected-chromedriver (not implemented to avoid heavy dep)
        self._log("All bypass layers exhausted", "error")
        return response if response else None
    
    def _try_cloudscraper(
        self,
        url: str,
        method: str,
        data: Dict,
        headers: Dict,
        timeout: int
    ) -> Optional[MockResponse]:
        """Try request with cloudscraper."""
        scraper = self._get_scraper()
        if not scraper:
            return None
        
        try:
            # Merge stealth headers
            final_headers = self.stealth.get_stealth_headers(url)
            if headers:
                final_headers.update(headers)
            
            if method.upper() == "GET":
                resp = scraper.get(url, headers=final_headers, timeout=timeout)
            else:
                resp = scraper.post(url, data=data, headers=final_headers, timeout=timeout)
            
            return MockResponse(resp.text, resp.status_code, dict(resp.headers), resp.url)
            
        except Exception as e:
            self._log(f"cloudscraper request failed: {e}", "warning")
            return None
    
    def get(self, url: str, params: Dict = None, timeout: int = 10) -> Optional[MockResponse]:
        """Convenience GET method."""
        return self.request(url, "GET", params=params, timeout=timeout)
    
    def post(self, url: str, data: Dict = None, timeout: int = 10) -> Optional[MockResponse]:
        """Convenience POST method."""
        return self.request(url, "POST", data=data, timeout=timeout)
    
    def close(self):
        """Clean up resources."""
        if self._browser:
            try:
                self._browser.close()
            except:
                pass
        if self._playwright:
            try:
                self._playwright.stop()
            except:
                pass
        self._browser = None
        self._context = None
        self._playwright = None
    
    def __enter__(self):
        return self
    
    def __exit__(self, *args):
        self.close()


def check_dependencies() -> Dict[str, bool]:
    """Check which CloudBuster dependencies are available."""
    return {
        "cloudscraper": CLOUDSCRAPER_AVAILABLE,
        "playwright": PLAYWRIGHT_STEALTH_AVAILABLE,
    }


def print_dependency_status():
    """Print status of CloudBuster dependencies."""
    deps = check_dependencies()
    console.print("\n[bold cyan]CloudBuster Dependencies:[/bold cyan]")
    for dep, available in deps.items():
        status = "[green]✓[/green]" if available else "[red]✗[/red]"
        install_cmd = ""
        if not available:
            if dep == "cloudscraper":
                install_cmd = " (pip install cloudscraper)"
            elif dep == "playwright":
                install_cmd = " (pip install playwright && playwright install)"
        console.print(f"  {status} {dep}{install_cmd}")
