# HikariSystem Tsurugi/modules/auth_crawl.py
"""
AUTH CRAWL - Session-Aware Authenticated Crawler
Crawls websites while maintaining an authenticated session.

Features:
- Automatic login form detection
- Session persistence with cookie jar
- CSRF token extraction and injection
- Session expiry detection and re-login
- Multi-step authentication support
"""
import re
import time
from urllib.parse import urljoin, urlparse, parse_qs
from typing import Dict, List, Set, Optional, Tuple
from dataclasses import dataclass
from bs4 import BeautifulSoup
from rich.progress import Progress, SpinnerColumn, TextColumn

from core.ui import console, log_info, log_success, log_warning, log_error
from core.requester import TsurugiSession
from core.logger import save_loot

@dataclass
class LoginConfig:
    """Configuration for authentication."""
    login_url: str
    username_field: str
    password_field: str
    username: str
    password: str
    success_indicator: str = None  # Text that appears after successful login
    logout_indicator: str = None   # Text that indicates session expired
    csrf_field: str = None         # CSRF token field name
    extra_fields: Dict = None      # Additional form fields

class AuthSession:
    """Manages authenticated session with auto-relogin."""
    
    def __init__(self, requester: TsurugiSession, config: LoginConfig):
        self.requester = requester
        self.config = config
        self.logged_in = False
        self.login_count = 0
        self.csrf_token = None
    
    def extract_csrf(self, html: str) -> Optional[str]:
        """Extract CSRF token from HTML."""
        soup = BeautifulSoup(html, 'html.parser')
        
        # Common CSRF field names
        csrf_names = ['csrf', 'csrf_token', '_token', 'csrfmiddlewaretoken', 
                      'authenticity_token', '__RequestVerificationToken', '_csrf']
        
        for name in csrf_names:
            # Try hidden input
            inp = soup.find('input', {'name': re.compile(name, re.I)})
            if inp and inp.get('value'):
                return inp['value']
            
            # Try meta tag
            meta = soup.find('meta', {'name': re.compile(name, re.I)})
            if meta and meta.get('content'):
                return meta['content']
        
        return None
    
    def login(self) -> bool:
        """Perform login and establish session."""
        try:
            # Get login page for CSRF
            login_resp = self.requester.get(self.config.login_url)
            if not login_resp:
                log_error("Failed to fetch login page")
                return False
            
            # Extract CSRF if present
            self.csrf_token = self.extract_csrf(login_resp.text)
            
            # Build login payload
            payload = {
                self.config.username_field: self.config.username,
                self.config.password_field: self.config.password,
            }
            
            if self.csrf_token and self.config.csrf_field:
                payload[self.config.csrf_field] = self.csrf_token
            elif self.csrf_token:
                # Try common CSRF field names
                for name in ['csrf', '_token', 'csrf_token']:
                    if name in login_resp.text.lower():
                        payload[name] = self.csrf_token
                        break
            
            if self.config.extra_fields:
                payload.update(self.config.extra_fields)
            
            # Perform login
            resp = self.requester.post(self.config.login_url, data=payload)
            
            if not resp:
                log_error("Login request failed")
                return False
            
            # Check for success
            if self.config.success_indicator:
                if self.config.success_indicator in resp.text:
                    self.logged_in = True
                    self.login_count += 1
                    log_success(f"Login successful (attempt #{self.login_count})")
                    return True
                else:
                    log_warning("Success indicator not found in response")
                    return False
            else:
                # Assume success if no errors and status is OK
                if resp.status_code in [200, 302, 303]:
                    self.logged_in = True
                    self.login_count += 1
                    log_success(f"Login appears successful (attempt #{self.login_count})")
                    return True
            
            return False
            
        except Exception as e:
            log_error(f"Login error: {e}")
            return False
    
    def check_session(self, response_text: str) -> bool:
        """Check if session is still valid."""
        if not self.config.logout_indicator:
            return True  # Can't check, assume valid
        
        if self.config.logout_indicator in response_text:
            log_warning("Session expired detected")
            self.logged_in = False
            return False
        
        return True
    
    def get(self, url: str, **kwargs) -> Optional:
        """GET request with session check and auto-relogin."""
        if not self.logged_in:
            if not self.login():
                return None
        
        resp = self.requester.get(url, **kwargs)
        
        if resp and not self.check_session(resp.text):
            # Session expired, re-login and retry
            if self.login():
                resp = self.requester.get(url, **kwargs)
        
        return resp

class AuthCrawler:
    """Authenticated web crawler."""
    
    def __init__(self, auth_session: AuthSession, max_depth: int = 3, 
                 max_pages: int = 100, same_origin: bool = True):
        self.auth = auth_session
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.same_origin = same_origin
        
        self.visited: Set[str] = set()
        self.to_visit: List[Tuple[str, int]] = []  # (url, depth)
        self.found_urls: Set[str] = set()
        self.found_forms: List[Dict] = []
        self.found_params: Set[str] = set()
        self.base_domain = None
    
    def normalize_url(self, url: str, base: str) -> Optional[str]:
        """Normalize URL and filter out non-HTTP links."""
        if not url:
            return None
        
        # Skip non-HTTP
        if url.startswith(('mailto:', 'tel:', 'javascript:', '#', 'data:')):
            return None
        
        # Make absolute
        full_url = urljoin(base, url)
        
        # Parse and clean
        parsed = urlparse(full_url)
        
        # Same origin check
        if self.same_origin and self.base_domain:
            if parsed.netloc != self.base_domain:
                return None
        
        # Remove fragment
        clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if parsed.query:
            clean_url += f"?{parsed.query}"
        
        return clean_url
    
    def extract_links(self, html: str, base_url: str) -> List[str]:
        """Extract all links from HTML."""
        soup = BeautifulSoup(html, 'html.parser')
        links = []
        
        # <a> tags
        for a in soup.find_all('a', href=True):
            url = self.normalize_url(a['href'], base_url)
            if url:
                links.append(url)
        
        # <form> actions
        for form in soup.find_all('form', action=True):
            url = self.normalize_url(form['action'], base_url)
            if url:
                links.append(url)
        
        # JavaScript URLs
        for script in soup.find_all('script'):
            if script.string:
                # Find URLs in JS
                js_urls = re.findall(r'["\'](/[a-zA-Z0-9_/\-\.]+)["\']', script.string)
                for js_url in js_urls:
                    url = self.normalize_url(js_url, base_url)
                    if url:
                        links.append(url)
        
        return links
    
    def extract_forms(self, html: str, base_url: str) -> List[Dict]:
        """Extract form details for vulnerability testing."""
        soup = BeautifulSoup(html, 'html.parser')
        forms = []
        
        for form in soup.find_all('form'):
            form_data = {
                'action': self.normalize_url(form.get('action', ''), base_url) or base_url,
                'method': form.get('method', 'GET').upper(),
                'inputs': [],
                'source_url': base_url,
            }
            
            for inp in form.find_all(['input', 'textarea', 'select']):
                name = inp.get('name')
                if name:
                    form_data['inputs'].append({
                        'name': name,
                        'type': inp.get('type', 'text'),
                        'value': inp.get('value', ''),
                    })
                    self.found_params.add(name)
            
            if form_data['inputs']:
                forms.append(form_data)
        
        return forms
    
    def crawl(self, start_url: str) -> Dict:
        """
        Perform authenticated crawl starting from URL.
        
        Returns:
            Dict with discovered URLs, forms, and parameters
        """
        parsed = urlparse(start_url)
        self.base_domain = parsed.netloc
        
        self.to_visit.append((start_url, 0))
        
        console.print(f"\n[bold cyan][AUTH CRAWL] Starting authenticated crawl[/bold cyan]")
        console.print(f"[dim]Target: {start_url}[/dim]")
        console.print(f"[dim]Max depth: {self.max_depth}, Max pages: {self.max_pages}[/dim]")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
        ) as progress:
            task = progress.add_task("[cyan]Crawling...", total=self.max_pages)
            
            while self.to_visit and len(self.visited) < self.max_pages:
                url, depth = self.to_visit.pop(0)
                
                if url in self.visited:
                    continue
                
                if depth > self.max_depth:
                    continue
                
                self.visited.add(url)
                progress.update(task, description=f"[cyan]Crawling ({len(self.visited)}/{self.max_pages})")
                
                # Fetch with auth
                resp = self.auth.get(url)
                if not resp:
                    continue
                
                self.found_urls.add(url)
                
                # Extract params from URL
                parsed = urlparse(url)
                if parsed.query:
                    for param in parse_qs(parsed.query).keys():
                        self.found_params.add(param)
                
                # Extract links
                links = self.extract_links(resp.text, url)
                for link in links:
                    if link not in self.visited:
                        self.to_visit.append((link, depth + 1))
                
                # Extract forms
                forms = self.extract_forms(resp.text, url)
                self.found_forms.extend(forms)
                
                progress.advance(task)
        
        # Results
        results = {
            'urls': list(self.found_urls),
            'forms': self.found_forms,
            'params': list(self.found_params),
            'stats': {
                'pages_crawled': len(self.visited),
                'urls_found': len(self.found_urls),
                'forms_found': len(self.found_forms),
                'params_found': len(self.found_params),
                'login_count': self.auth.login_count,
            }
        }
        
        return results

def run_auth_crawl(start_url: str, login_url: str, username: str, password: str,
                   username_field: str = "username", password_field: str = "password",
                   success_indicator: str = None, logout_indicator: str = None,
                   depth: int = 3, max_pages: int = 100,
                   cookie: str = None, proxy: str = None) -> Optional[Dict]:
    """
    Run authenticated crawl.
    
    Args:
        start_url: URL to start crawling from
        login_url: Login form URL
        username/password: Credentials
        username_field/password_field: Form field names
        success_indicator: Text that appears after successful login
        logout_indicator: Text that indicates session expired
    """
    console.print(f"\n[bold green][AUTH CRAWL] Session-Aware Authenticated Crawler[/bold green]")
    
    requester = TsurugiSession(cookie_string=cookie, proxy=proxy)
    
    config = LoginConfig(
        login_url=login_url,
        username_field=username_field,
        password_field=password_field,
        username=username,
        password=password,
        success_indicator=success_indicator,
        logout_indicator=logout_indicator,
    )
    
    auth = AuthSession(requester, config)
    
    # Perform initial login
    log_info(f"Attempting login to {login_url}")
    if not auth.login():
        log_error("Initial login failed. Check credentials and field names.")
        return None
    
    # Create crawler
    crawler = AuthCrawler(auth, max_depth=depth, max_pages=max_pages)
    
    # Crawl
    results = crawler.crawl(start_url)
    
    # Report
    console.print(f"\n[bold green][+] CRAWL COMPLETE[/bold green]")
    console.print(f"  Pages crawled: {results['stats']['pages_crawled']}")
    console.print(f"  URLs found: {results['stats']['urls_found']}")
    console.print(f"  Forms found: {results['stats']['forms_found']}")
    console.print(f"  Parameters: {results['stats']['params_found']}")
    console.print(f"  Re-logins: {results['stats']['login_count'] - 1}")
    
    if results['params']:
        console.print(f"\n[cyan]Discovered Parameters:[/cyan]")
        for param in sorted(results['params'])[:20]:
            console.print(f"  - {param}")
        if len(results['params']) > 20:
            console.print(f"  ... and {len(results['params']) - 20} more")
    
    # Save results
    save_loot("auth_crawl", start_url, results)
    
    return results
