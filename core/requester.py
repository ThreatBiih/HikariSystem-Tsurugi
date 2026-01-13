# HikariSystem Tsurugi/core/requester.py
"""
TSURUGI SESSION - TLS Stealth HTTP Client
Uses curl_cffi for browser TLS fingerprint impersonation (JA3/JA4 spoofing).
Falls back to requests if curl_cffi is unavailable.
"""
import time
import random
from typing import Dict, Optional, Any
from core.ui import console, log_info, log_warning, log_error

# TLS fingerprint profiles (browser impersonation)
TLS_PROFILES = [
    "chrome110", "chrome116", "chrome119", "chrome120", "chrome123",
    "safari15_5", "safari17_0",
    "firefox109", "firefox117",
    "edge101", "edge99"
]

# Try to import curl_cffi for TLS stealth
_USE_CURL_CFFI = False
try:
    from curl_cffi import requests as cffi_requests
    _USE_CURL_CFFI = True
except ImportError:
    import requests
    log_warning("curl_cffi not installed. TLS fingerprinting disabled.")
    log_warning("Install with: pip install curl_cffi")


class ProxyPool:
    """Proxy pool with automatic rotation and health tracking."""
    
    def __init__(self, proxies: list = None, proxy_file: str = None):
        self.proxies = []
        self.dead_proxies = set()
        self.current_index = 0
        
        if proxies:
            self.proxies = list(proxies)
        elif proxy_file:
            self._load_from_file(proxy_file)
    
    def _load_from_file(self, filepath: str):
        """Load proxies from file (one per line)."""
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    proxy = line.strip()
                    if proxy and not proxy.startswith('#'):
                        if not proxy.startswith('http'):
                            proxy = f"http://{proxy}"
                        self.proxies.append(proxy)
        except Exception as e:
            log_warning(f"Failed to load proxy file: {e}")
    
    def get_proxy(self) -> str:
        """Get next available proxy."""
        if not self.proxies:
            return None
        
        alive = [p for p in self.proxies if p not in self.dead_proxies]
        if not alive:
            # Reset dead list if all dead
            self.dead_proxies.clear()
            alive = self.proxies
        
        proxy = alive[self.current_index % len(alive)]
        self.current_index += 1
        return proxy
    
    def mark_dead(self, proxy: str):
        """Mark proxy as dead."""
        self.dead_proxies.add(proxy)
        log_warning(f"Proxy marked dead: {proxy}")
    
    def rotate(self) -> str:
        """Force rotation to next proxy."""
        self.current_index += 1
        return self.get_proxy()
    
    def __bool__(self):
        return bool(self.proxies)


class TsurugiSession:
    """
    Advanced HTTP session with TLS fingerprint spoofing.
    
    Features:
    - Browser TLS fingerprint impersonation (JA3/JA4)
    - Auto-rotate fingerprint on WAF block
    - Cookie persistence
    - Proxy support
    - Stealth mode (delays + header rotation)
    """
    
    def __init__(self, 
                 cookie_string: str = None,
                 proxy: str = None,
                 impersonate: str = "chrome120",
                 stealth: bool = False,
                 cf_bypass: bool = False,
                 timeout: int = 15):
        """
        Initialize session.
        
        Args:
            cookie_string: Cookies in "name=value; name2=value2" format
            proxy: Proxy URL (http://host:port)
            impersonate: Browser profile for TLS fingerprint
            stealth: Enable stealth mode (delays + header rotation)
            cf_bypass: Enable Cloudflare bypass attempts
            timeout: Request timeout in seconds
        """
        self.proxy = proxy
        self.timeout = timeout
        self.stealth = stealth
        self.cf_bypass = cf_bypass
        self.impersonate = impersonate
        self.cookies = self._parse_cookies(cookie_string) if cookie_string else {}
        self.request_count = 0
        self.block_count = 0
        
        # Adaptive rate limiting
        self.base_delay = 0.1
        self.backoff_multiplier = 1.0
        self.max_backoff = 30.0
        self.last_429_time = 0
        self.rate_limit_window = {}  # host -> request count
        
        # Proxy pool
        self.proxy_pool = None
        self.current_proxy = proxy
        
        # Headers that rotate in stealth mode
        self._user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/117.0",
        ]
        
        # Create session
        self._create_session()
    
    def _create_session(self):
        """Create HTTP session with appropriate backend."""
        if _USE_CURL_CFFI:
            self.session = cffi_requests.Session(
                impersonate=self.impersonate,
                headers=self._get_base_headers(),
                timeout=self.timeout
            )
            if self.proxy:
                self.session.proxies = {"http": self.proxy, "https": self.proxy}
        else:
            import requests
            self.session = requests.Session()
            self.session.headers.update(self._get_base_headers())
            if self.proxy:
                self.session.proxies = {"http": self.proxy, "https": self.proxy}
    
    def _get_base_headers(self) -> Dict[str, str]:
        """Get base headers for requests."""
        return {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Cache-Control": "max-age=0",
        }
    
    def _parse_cookies(self, cookie_string: str) -> Dict[str, str]:
        """Parse cookie string into dict."""
        cookies = {}
        if not cookie_string:
            return cookies
        try:
            for pair in cookie_string.split(';'):
                pair = pair.strip()
                if '=' in pair:
                    key, value = pair.split('=', 1)
                    cookies[key.strip()] = value.strip()
        except Exception:
            pass
        return cookies
    
    def _stealth_delay(self):
        """Add random delay in stealth mode with adaptive backoff."""
        if self.stealth:
            # Base delay + random + backoff
            delay = (self.base_delay + random.uniform(0.3, 1.5)) * self.backoff_multiplier
            delay = min(delay, self.max_backoff)
            time.sleep(delay)
        elif self.backoff_multiplier > 1:
            # Even without stealth, respect backoff after 429
            time.sleep(self.base_delay * self.backoff_multiplier)
    
    def _handle_rate_limit(self, response):
        """Handle 429 response with exponential backoff."""
        if response and response.status_code == 429:
            self.backoff_multiplier = min(self.backoff_multiplier * 2, 16)
            self.last_429_time = time.time()
            
            # Check for Retry-After header
            retry_after = response.headers.get('Retry-After')
            if retry_after:
                try:
                    wait = int(retry_after)
                    console.print(f"[yellow][*] Rate limited. Waiting {wait}s (Retry-After)[/yellow]")
                    time.sleep(wait)
                    return
                except ValueError:
                    pass
            
            console.print(f"[yellow][*] 429 detected. Backoff: {self.backoff_multiplier}x[/yellow]")
            time.sleep(self.base_delay * self.backoff_multiplier)
        else:
            # Gradually reduce backoff on success
            if time.time() - self.last_429_time > 30:
                self.backoff_multiplier = max(1.0, self.backoff_multiplier * 0.8)
    
    def set_proxy_pool(self, proxies: list = None, proxy_file: str = None):
        """Configure proxy pool for rotation."""
        self.proxy_pool = ProxyPool(proxies=proxies, proxy_file=proxy_file)
        if self.proxy_pool:
            self.current_proxy = self.proxy_pool.get_proxy()
            console.print(f"[cyan][*] Proxy pool initialized: {len(self.proxy_pool.proxies)} proxies[/cyan]")
    
    def rotate_proxy(self):
        """Rotate to next proxy in pool."""
        if self.proxy_pool:
            old_proxy = self.current_proxy
            self.current_proxy = self.proxy_pool.rotate()
            if self.current_proxy != old_proxy:
                self._create_session()  # Recreate session with new proxy
                console.print(f"[yellow][*] Proxy rotated: {self.current_proxy}[/yellow]")
    
    def _rotate_headers(self, headers: Dict) -> Dict:
        """Rotate headers in stealth mode."""
        if self.stealth:
            headers = headers.copy() if headers else {}
            headers["User-Agent"] = random.choice(self._user_agents)
        return headers
    
    def rotate_fingerprint(self):
        """Rotate TLS fingerprint on WAF block."""
        old_profile = self.impersonate
        self.impersonate = random.choice([p for p in TLS_PROFILES if p != old_profile])
        self._create_session()
        console.print(f"[yellow][*] TLS Fingerprint rotated: {old_profile} -> {self.impersonate}[/yellow]")
    
    def _is_waf_block(self, response) -> bool:
        """Detect if response is a WAF block."""
        if response is None:
            return True
        
        # Status code checks
        if response.status_code in [403, 429, 503]:
            # Check for WAF signatures
            body = response.text.lower() if hasattr(response, 'text') else ''
            waf_signatures = [
                'cloudflare', 'attention required', 'just a moment',
                'access denied', 'blocked', 'rate limit',
                'akamai', 'incapsula', 'sucuri', 'ddos',
                'captcha', 'challenge', 'security check'
            ]
            return any(sig in body for sig in waf_signatures)
        
        return False
    
    def get(self, url: str, params: Dict = None, timeout: int = None, 
            headers: Dict = None, allow_redirects: bool = True, **kwargs) -> Optional[Any]:
        """
        GET request with TLS stealth and auto-retry on WAF block.
        """
        return self._request("GET", url, params=params, timeout=timeout,
                            headers=headers, allow_redirects=allow_redirects, **kwargs)
    
    def post(self, url: str, data: Dict = None, json: Dict = None,
             timeout: int = None, headers: Dict = None, **kwargs) -> Optional[Any]:
        """
        POST request with TLS stealth and auto-retry on WAF block.
        """
        return self._request("POST", url, data=data, json=json,
                            timeout=timeout, headers=headers, **kwargs)
    
    def _request(self, method: str, url: str, max_retries: int = 2, **kwargs) -> Optional[Any]:
        """
        Execute HTTP request with TLS stealth.
        
        Features:
        - Browser TLS fingerprint
        - Auto-rotate on WAF block
        - Stealth delays
        - Cookie injection
        """
        self._stealth_delay()
        self.request_count += 1
        
        # Prepare headers
        headers = self._rotate_headers(kwargs.pop('headers', None) or {})
        
        # Merge cookies
        request_cookies = {**self.cookies, **kwargs.pop('cookies', {})}
        
        # Set timeout
        timeout = kwargs.pop('timeout', None) or self.timeout
        
        for attempt in range(max_retries + 1):
            try:
                if _USE_CURL_CFFI:
                    response = self.session.request(
                        method, url,
                        headers=headers,
                        cookies=request_cookies,
                        timeout=timeout,
                        **kwargs
                    )
                else:
                    response = self.session.request(
                        method, url,
                        headers=headers,
                        cookies=request_cookies,
                        timeout=timeout,
                        **kwargs
                    )
                
                # Check for WAF block
                if self._is_waf_block(response):
                    self.block_count += 1
                    if attempt < max_retries:
                        console.print(f"[yellow][!] WAF block detected. Rotating fingerprint (attempt {attempt + 1})...[/yellow]")
                        self.rotate_fingerprint()
                        if self.proxy_pool:
                            self.rotate_proxy()
                        self._stealth_delay()
                        continue
                    else:
                        log_warning(f"WAF block persists after {max_retries} retries")
                
                # Handle rate limiting
                self._handle_rate_limit(response)
                
                return response
                
            except Exception as e:
                if attempt < max_retries:
                    # Rotate proxy on failure
                    if self.proxy_pool:
                        self.proxy_pool.mark_dead(self.current_proxy)
                        self.rotate_proxy()
                    self.rotate_fingerprint()
                    continue
                log_error(f"Request failed: {e}")
                return None
        
        return None
    
    def get_stats(self) -> Dict:
        """Get session statistics."""
        return {
            "requests": self.request_count,
            "blocks": self.block_count,
            "current_profile": self.impersonate,
            "tls_stealth": _USE_CURL_CFFI,
        }
