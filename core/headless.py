# HikariSystem Tsurugi/core/headless.py
"""
HEADLESS ENGINE - Playwright-based browser with stealth patches.
Default engine for reconnaissance and crawling.
Renders JavaScript, intercepts Network requests, detects DOM sinks.

Features:
- Full JavaScript execution (SPAs, React, Vue, Angular)
- Stealth mode (anti-detection patches)
- Network interception (API endpoint discovery)
- DOM sink detection (DOM XSS vectors)
- Auto-scroll for lazy-loaded content
- Cookie/proxy injection
"""
import asyncio
from typing import List, Dict, Optional, Set, Any
from dataclasses import dataclass, field
from urllib.parse import urlparse, urljoin

# Check for playwright availability
_PLAYWRIGHT_AVAILABLE = False
try:
    from playwright.async_api import async_playwright, Page, BrowserContext, Browser
    _PLAYWRIGHT_AVAILABLE = True
except ImportError:
    pass

# Check for stealth patches
_STEALTH_AVAILABLE = False
_STEALTH_CLASS = None
try:
    from playwright_stealth import Stealth
    _STEALTH_AVAILABLE = True
    _STEALTH_CLASS = Stealth()
except ImportError:
    try:
        from playwright_stealth import stealth_async
        _STEALTH_AVAILABLE = True
    except ImportError:
        pass

from core.ui import console, log_info, log_success, log_warning, log_error


@dataclass
class NetworkRequest:
    """Captured network request."""
    url: str
    method: str
    resource_type: str
    headers: Dict[str, str] = field(default_factory=dict)
    post_data: Optional[str] = None


@dataclass
class HeadlessResult:
    """Result from headless page load."""
    url: str
    html: str
    title: str
    status_code: int
    network_requests: List[NetworkRequest] = field(default_factory=list)
    api_endpoints: List[str] = field(default_factory=list)
    js_files: List[str] = field(default_factory=list)
    dom_sinks: List[Dict] = field(default_factory=list)
    cookies: List[Dict] = field(default_factory=list)
    error: Optional[str] = None


class HeadlessEngine:
    """
    Playwright-based browser engine with stealth patches.
    
    Usage:
        async with HeadlessEngine(proxy="http://127.0.0.1:8080") as engine:
            result = await engine.get("https://target.com")
            print(result.api_endpoints)
    """
    
    def __init__(self,
                 cookie_string: str = None,
                 proxy: str = None,
                 headless: bool = True,
                 timeout: int = 30000,
                 user_agent: str = None):
        """
        Initialize headless engine.
        
        Args:
            cookie_string: Cookies in "name=value; name2=value2" format
            proxy: Proxy URL (http://host:port) 
            headless: Run browser in headless mode
            timeout: Navigation timeout in milliseconds
            user_agent: Custom user agent
        """
        if not _PLAYWRIGHT_AVAILABLE:
            raise ImportError("Playwright not installed. Run: pip install playwright && playwright install chromium")
        
        self.cookie_string = cookie_string
        self.proxy = proxy
        self.headless = headless
        self.timeout = timeout
        self.user_agent = user_agent or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        
        self._playwright = None
        self._browser: Browser = None
        self._context: BrowserContext = None
        self._page: Page = None
        
        # Network capture
        self._network_requests: List[NetworkRequest] = []
        self._api_endpoints: Set[str] = set()
        self._js_files: Set[str] = set()
    
    async def __aenter__(self):
        """Start browser on context entry."""
        await self._start_browser()
        return self
    
    async def __aexit__(self, *args):
        """Close browser on context exit."""
        await self._close_browser()
    
    async def _start_browser(self):
        """Initialize Playwright browser with stealth."""
        self._playwright = await async_playwright().start()
        
        # Browser launch options
        launch_options = {
            "headless": self.headless,
        }
        
        # Proxy configuration
        if self.proxy:
            launch_options["proxy"] = {"server": self.proxy}
        
        self._browser = await self._playwright.chromium.launch(**launch_options)
        
        # Context options
        context_options = {
            "user_agent": self.user_agent,
            "viewport": {"width": 1920, "height": 1080},
            "ignore_https_errors": True,
            "java_script_enabled": True,
        }
        
        self._context = await self._browser.new_context(**context_options)
        
        # Inject cookies
        if self.cookie_string:
            await self._inject_cookies()
        
        self._page = await self._context.new_page()
        
        # Apply stealth patches
        if _STEALTH_AVAILABLE:
            if _STEALTH_CLASS:
                await _STEALTH_CLASS.apply_stealth_async(self._page)
            else:
                await stealth_async(self._page)
        else:
            log_warning("playwright-stealth not installed. Anti-detection limited.")
        
        # Setup network interception
        await self._setup_network_capture()
        
        log_info(f"Headless engine started (stealth: {_STEALTH_AVAILABLE})")
    
    async def _close_browser(self):
        """Clean up browser resources."""
        if self._context:
            await self._context.close()
        if self._browser:
            await self._browser.close()
        if self._playwright:
            await self._playwright.stop()
    
    async def _inject_cookies(self):
        """Parse and inject cookies into context."""
        if not self.cookie_string:
            return
        
        cookies = []
        for pair in self.cookie_string.split(";"):
            pair = pair.strip()
            if "=" in pair:
                name, value = pair.split("=", 1)
                cookies.append({
                    "name": name.strip(),
                    "value": value.strip(),
                    "domain": "",  # Will be set per-request
                    "path": "/",
                })
        
        if cookies:
            # We'll inject cookies after first navigation
            self._pending_cookies = cookies
    
    async def _setup_network_capture(self):
        """Setup request interception for API discovery."""
        
        async def on_request(request):
            """Capture outgoing requests."""
            url = request.url
            method = request.method
            resource_type = request.resource_type
            
            # Capture API endpoints (XHR/Fetch)
            if resource_type in ["xhr", "fetch"]:
                self._api_endpoints.add(url)
            
            # Capture JS files
            if resource_type == "script" or url.endswith(".js"):
                self._js_files.add(url)
            
            # Store request details
            self._network_requests.append(NetworkRequest(
                url=url,
                method=method,
                resource_type=resource_type,
                headers=dict(request.headers),
                post_data=request.post_data if method == "POST" else None
            ))
        
        self._page.on("request", on_request)
    
    async def _auto_scroll(self):
        """Scroll page to trigger lazy-loaded content."""
        try:
            await self._page.evaluate('''async () => {
                await new Promise((resolve) => {
                    let totalHeight = 0;
                    const distance = 300;
                    const timer = setInterval(() => {
                        const scrollHeight = document.body.scrollHeight;
                        window.scrollBy(0, distance);
                        totalHeight += distance;
                        
                        if (totalHeight >= scrollHeight) {
                            clearInterval(timer);
                            window.scrollTo(0, 0);
                            resolve();
                        }
                    }, 100);
                });
            }''')
        except Exception:
            pass
    
    async def _find_dom_sinks(self) -> List[Dict]:
        """Detect potential DOM XSS sinks in the page."""
        try:
            sinks = await self._page.evaluate('''() => {
                const sinks = [];
                const dangerous = [
                    'innerHTML', 'outerHTML', 'insertAdjacentHTML',
                    'document.write', 'document.writeln',
                    'eval', 'setTimeout', 'setInterval',
                    'location', 'location.href', 'location.assign',
                    'location.replace', 'document.location'
                ];
                
                // Check for inline event handlers
                const handlers = document.querySelectorAll('[onclick], [onerror], [onload], [onmouseover]');
                handlers.forEach(el => {
                    sinks.push({
                        type: 'event_handler',
                        element: el.tagName,
                        attributes: Array.from(el.attributes).map(a => a.name).filter(n => n.startsWith('on'))
                    });
                });
                
                // Check for javascript: URLs
                const jsLinks = document.querySelectorAll('a[href^="javascript:"]');
                jsLinks.forEach(el => {
                    sinks.push({
                        type: 'javascript_url',
                        element: 'a',
                        href: el.href.substring(0, 100)
                    });
                });
                
                // Check for document.location usage in scripts
                const scripts = document.querySelectorAll('script:not([src])');
                scripts.forEach(script => {
                    const code = script.textContent;
                    if (code.includes('location.hash') || 
                        code.includes('location.search') ||
                        code.includes('document.URL') ||
                        code.includes('document.referrer')) {
                        sinks.push({
                            type: 'url_source',
                            snippet: code.substring(0, 200)
                        });
                    }
                });
                
                return sinks;
            }''')
            return sinks
        except Exception as e:
            return []
    
    async def get(self, url: str, 
                  wait_for: str = "networkidle",
                  auto_scroll: bool = True,
                  detect_sinks: bool = True) -> HeadlessResult:
        """
        Navigate to URL and capture full page state.
        
        Args:
            url: Target URL
            wait_for: Wait condition (networkidle, load, domcontentloaded)
            auto_scroll: Scroll page to trigger lazy loading
            detect_sinks: Run DOM sink detection
            
        Returns:
            HeadlessResult with HTML, network requests, API endpoints, etc.
        """
        # Reset captures
        self._network_requests = []
        self._api_endpoints = set()
        self._js_files = set()
        
        try:
            # Navigate
            response = await self._page.goto(
                url,
                wait_until=wait_for,
                timeout=self.timeout
            )
            
            status_code = response.status if response else 0
            
            # Wait a bit more for dynamic content
            await asyncio.sleep(1)
            
            # Auto-scroll
            if auto_scroll:
                await self._auto_scroll()
                await asyncio.sleep(0.5)
            
            # Get final HTML
            html = await self._page.content()
            title = await self._page.title()
            
            # Detect DOM sinks
            dom_sinks = []
            if detect_sinks:
                dom_sinks = await self._find_dom_sinks()
            
            # Get cookies
            cookies = await self._context.cookies()
            
            return HeadlessResult(
                url=url,
                html=html,
                title=title,
                status_code=status_code,
                network_requests=self._network_requests.copy(),
                api_endpoints=list(self._api_endpoints),
                js_files=list(self._js_files),
                dom_sinks=dom_sinks,
                cookies=cookies
            )
            
        except Exception as e:
            return HeadlessResult(
                url=url,
                html="",
                title="",
                status_code=0,
                error=str(e)
            )
    
    async def get_rendered_html(self, url: str) -> str:
        """Simple method to get just the rendered HTML."""
        result = await self.get(url, auto_scroll=False, detect_sinks=False)
        return result.html
    
    async def execute_js(self, script: str) -> Any:
        """Execute JavaScript in page context."""
        return await self._page.evaluate(script)
    
    async def screenshot(self, path: str = None) -> bytes:
        """Take screenshot of current page."""
        return await self._page.screenshot(path=path, full_page=True)
    
    async def fill_form(self, selector: str, value: str):
        """Fill a form field."""
        await self._page.fill(selector, value)
    
    async def click(self, selector: str):
        """Click an element."""
        await self._page.click(selector)


# Convenience function for single-page loads
async def headless_get(url: str, 
                       cookie: str = None, 
                       proxy: str = None) -> HeadlessResult:
    """
    Quick headless fetch of a single URL.
    
    Example:
        result = await headless_get("https://spa-app.com")
        print(result.api_endpoints)
    """
    async with HeadlessEngine(cookie_string=cookie, proxy=proxy) as engine:
        return await engine.get(url)


def run_headless_get(url: str, cookie: str = None, proxy: str = None) -> HeadlessResult:
    """Synchronous wrapper for headless_get."""
    return asyncio.run(headless_get(url, cookie, proxy))


# Check availability
def is_headless_available() -> bool:
    """Check if headless engine is available."""
    return _PLAYWRIGHT_AVAILABLE
