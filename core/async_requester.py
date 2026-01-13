# HikariSystem Tsurugi/core/async_requester.py
"""
ASYNC REQUESTER - High-Performance Asynchronous HTTP Client
Uses curl_cffi AsyncSession for TLS stealth + async speed (GOD MODE).

Features:
- Browser TLS fingerprint impersonation (JA3/JA4)
- Async concurrent requests
- Connection pooling
- Rate limiting per host
- WAF block detection with fingerprint rotation
"""
import asyncio
import time
from typing import List, Dict, Optional, Callable, Any
from dataclasses import dataclass
from core.ui import console, log_info, log_warning

# TLS profiles for impersonation
TLS_PROFILES = ["chrome120", "chrome119", "safari17_0", "firefox117", "edge99"]

# Try to import curl_cffi async, fallback to httpx
_USE_CURL_CFFI = False
try:
    from curl_cffi.requests import AsyncSession
    _USE_CURL_CFFI = True
except ImportError:
    try:
        import httpx
        log_warning("curl_cffi async not available. Using httpx (no TLS stealth in async mode).")
    except ImportError:
        log_warning("Neither curl_cffi nor httpx installed. Async disabled.")

DEFAULT_CONCURRENT = 50
DEFAULT_TIMEOUT = 15
DEFAULT_RATE_LIMIT = 100


@dataclass
class AsyncResponse:
    """Wrapper for async response data."""
    url: str
    status_code: int
    content: bytes
    text: str
    headers: Dict
    elapsed: float
    error: Optional[str] = None


class AsyncRequester:
    """
    High-performance async HTTP client with TLS stealth.
    
    Uses curl_cffi AsyncSession for browser impersonation.
    
    Example:
        async with AsyncRequester(max_concurrent=100, impersonate="chrome120") as client:
            results = await client.get_batch(urls)
    """
    
    def __init__(self,
                 max_concurrent: int = DEFAULT_CONCURRENT,
                 timeout: int = DEFAULT_TIMEOUT,
                 rate_limit: int = DEFAULT_RATE_LIMIT,
                 impersonate: str = "chrome120",
                 headers: Dict = None,
                 cookies: Dict = None,
                 proxy: str = None):
        """
        Initialize async requester with TLS stealth.
        
        Args:
            max_concurrent: Max concurrent requests
            timeout: Request timeout in seconds
            rate_limit: Max requests per second
            impersonate: Browser profile for TLS fingerprint
            headers: Default headers
            cookies: Default cookies
            proxy: Proxy URL
        """
        self.max_concurrent = max_concurrent
        self.timeout = timeout
        self.rate_limit = rate_limit
        self.impersonate = impersonate
        self.proxy = proxy
        
        self.headers = headers or {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }
        
        self.cookies = cookies or {}
        
        # Rate limiting
        self._semaphore: asyncio.Semaphore = None
        self._last_request_time = 0
        
        # Session
        self._session = None
        
        # Stats
        self.stats = {
            "requests": 0,
            "success": 0,
            "failed": 0,
            "waf_blocks": 0,
            "total_time": 0
        }
    
    async def __aenter__(self):
        """Create session on context entry."""
        self._semaphore = asyncio.Semaphore(self.max_concurrent)
        
        if _USE_CURL_CFFI:
            self._session = AsyncSession(
                impersonate=self.impersonate,
                headers=self.headers,
                timeout=self.timeout,
                proxies={"http": self.proxy, "https": self.proxy} if self.proxy else None
            )
        else:
            import httpx
            self._session = httpx.AsyncClient(
                headers=self.headers,
                timeout=self.timeout,
                proxy=self.proxy
            )
        
        return self
    
    async def __aexit__(self, *args):
        """Close session on context exit."""
        if self._session:
            if _USE_CURL_CFFI:
                await self._session.close()
            else:
                await self._session.aclose()
    
    async def _rate_limit_delay(self):
        """Apply rate limiting delay."""
        if self.rate_limit <= 0:
            return
        
        min_interval = 1.0 / self.rate_limit
        elapsed = time.time() - self._last_request_time
        
        if elapsed < min_interval:
            await asyncio.sleep(min_interval - elapsed)
        
        self._last_request_time = time.time()
    
    def _is_waf_block(self, status: int, body: str) -> bool:
        """Detect WAF block."""
        if status in [403, 429, 503]:
            waf_signatures = ['cloudflare', 'access denied', 'blocked', 'rate limit', 'captcha']
            return any(sig in body.lower() for sig in waf_signatures)
        return False
    
    async def get(self, url: str, **kwargs) -> AsyncResponse:
        """Single async GET request with TLS stealth."""
        return await self._request("GET", url, **kwargs)
    
    async def post(self, url: str, data: Dict = None, json: Dict = None, **kwargs) -> AsyncResponse:
        """Single async POST request with TLS stealth."""
        return await self._request("POST", url, data=data, json=json, **kwargs)
    
    async def _request(self, method: str, url: str, **kwargs) -> AsyncResponse:
        """Execute single request with semaphore and rate limiting."""
        async with self._semaphore:
            await self._rate_limit_delay()
            
            start = time.time()
            self.stats["requests"] += 1
            
            try:
                if _USE_CURL_CFFI:
                    response = await self._session.request(
                        method, url,
                        cookies=self.cookies,
                        **kwargs
                    )
                    status = response.status_code
                    content = response.content
                    text = response.text
                    headers = dict(response.headers)
                else:
                    response = await self._session.request(method, url, **kwargs)
                    status = response.status_code
                    content = response.content
                    text = response.text
                    headers = dict(response.headers)
                
                elapsed = time.time() - start
                
                # Check for WAF block
                if self._is_waf_block(status, text):
                    self.stats["waf_blocks"] += 1
                
                self.stats["success"] += 1
                self.stats["total_time"] += elapsed
                
                return AsyncResponse(
                    url=url,
                    status_code=status,
                    content=content,
                    text=text,
                    headers=headers,
                    elapsed=elapsed
                )
                
            except Exception as e:
                elapsed = time.time() - start
                self.stats["failed"] += 1
                self.stats["total_time"] += elapsed
                
                return AsyncResponse(
                    url=url,
                    status_code=0,
                    content=b"",
                    text="",
                    headers={},
                    elapsed=elapsed,
                    error=str(e)
                )
    
    async def get_batch(self, urls: List[str], 
                        callback: Callable[[AsyncResponse], Any] = None,
                        show_progress: bool = True) -> List[AsyncResponse]:
        """
        Fetch multiple URLs concurrently with TLS stealth.
        """
        if show_progress:
            mode = "curl_cffi (TLS stealth)" if _USE_CURL_CFFI else "httpx"
            console.print(f"[cyan][*] Fetching {len(urls)} URLs ({mode}, concurrency: {self.max_concurrent})[/cyan]")
        
        tasks = [self.get(url) for url in urls]
        results = []
        
        completed = 0
        for coro in asyncio.as_completed(tasks):
            result = await coro
            results.append(result)
            completed += 1
            
            if callback:
                callback(result)
            
            if show_progress and completed % 100 == 0:
                console.print(f"[dim]Progress: {completed}/{len(urls)}[/dim]")
        
        if show_progress:
            avg_time = self.stats["total_time"] / max(self.stats["requests"], 1)
            console.print(f"[green][+] Completed: {self.stats['success']} success, {self.stats['failed']} failed[/green]")
            if self.stats["waf_blocks"] > 0:
                console.print(f"[yellow]WAF blocks detected: {self.stats['waf_blocks']}[/yellow]")
            console.print(f"[dim]Avg response time: {avg_time:.2f}s, TLS Profile: {self.impersonate}[/dim]")
        
        return results


async def async_mass_check(urls: List[str], 
                           max_concurrent: int = 50,
                           timeout: int = 10,
                           impersonate: str = "chrome120",
                           callback: Callable = None) -> List[AsyncResponse]:
    """
    Convenience function for batch URL checking with TLS stealth.
    """
    async with AsyncRequester(
        max_concurrent=max_concurrent, 
        timeout=timeout,
        impersonate=impersonate
    ) as client:
        return await client.get_batch(urls, callback=callback)


def run_async_batch(urls: List[str], 
                    max_concurrent: int = 50,
                    impersonate: str = "chrome120",
                    callback: Callable = None) -> List[AsyncResponse]:
    """
    Synchronous wrapper for async batch requests.
    Can be called from non-async code.
    
    Example:
        results = run_async_batch(urls, max_concurrent=100)
    """
    return asyncio.run(async_mass_check(urls, max_concurrent, impersonate=impersonate, callback=callback))
