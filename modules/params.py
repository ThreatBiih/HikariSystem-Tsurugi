# HikariSystem Tsurugi/modules/params.py
"""
PARAMETER DISCOVERY MODULE
Discovers hidden parameters in endpoints using fuzzing and response comparison
"""
import hashlib
from typing import Dict, List, Optional, Set
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.ui import console, log_info, log_success, log_warning, log_error
from core.requester import TsurugiSession
from core.logger import save_loot
from rich.table import Table
from rich.progress import Progress

# Common hidden parameters wordlist
PARAM_WORDLIST = [
    # Debug/Admin
    "debug", "admin", "test", "testing", "dev", "development", "staging",
    "verbose", "trace", "log", "logging", "internal", "hidden", "secret",
    
    # Auth/Session
    "token", "auth", "api_key", "apikey", "key", "secret", "password",
    "pass", "pwd", "session", "sid", "jwt", "bearer", "access_token",
    "refresh_token", "oauth", "sso", "login", "user", "username",
    
    # Common params
    "id", "uid", "userid", "user_id", "account", "account_id", "customer",
    "order", "order_id", "item", "product", "product_id", "sku",
    "page", "limit", "offset", "size", "count", "start", "end",
    "sort", "order", "filter", "search", "query", "q", "s",
    
    # Config/Settings
    "config", "configuration", "settings", "options", "mode", "type",
    "format", "output", "response", "callback", "jsonp", "cors",
    
    # File/Path
    "file", "filename", "path", "url", "uri", "src", "source", "dest",
    "destination", "dir", "directory", "folder", "include", "require",
    "template", "view", "layout", "theme",
    
    # Action/Command
    "action", "cmd", "command", "exec", "execute", "run", "do", "op",
    "operation", "method", "function", "func", "handler", "controller",
    
    # Redirect
    "redirect", "redirect_url", "redirect_uri", "return", "return_url",
    "next", "continue", "goto", "target", "to", "from", "ref", "referer",
    
    # API specific
    "version", "v", "api", "api_version", "format", "fields", "include",
    "exclude", "expand", "embed", "populate", "with", "relationships",
    
    # Cache/Proxy
    "cache", "nocache", "refresh", "reload", "bypass", "proxy", "forward",
    
    # Misc
    "env", "environment", "locale", "lang", "language", "region", "country",
    "currency", "timezone", "tz", "date", "time", "timestamp", "ts",
    "random", "rand", "nonce", "salt", "hash", "checksum", "signature",
    "callback", "hook", "event", "trigger", "notify", "email", "phone",
    
    # Boolean flags
    "enabled", "disabled", "active", "inactive", "on", "off", "true", "false",
    "yes", "no", "show", "hide", "public", "private", "raw", "pretty",
    
    # Dangerous
    "rce", "shell", "system", "eval", "code", "script", "payload",
]

# Test values for different param types
TEST_VALUES = {
    "string": "tsurugitest123",
    "number": "1337",
    "boolean": "true",
    "empty": "",
}


def get_response_signature(response) -> dict:
    """Calculate response signature for comparison."""
    if not response:
        return {"status": 0, "length": 0, "hash": ""}
    
    return {
        "status": response.status_code,
        "length": len(response.text),
        "hash": hashlib.md5(response.text.encode()).hexdigest()[:16]
    }


def signatures_differ(sig1: dict, sig2: dict, threshold: int = 50) -> bool:
    """Check if two response signatures are significantly different."""
    if sig1["status"] != sig2["status"]:
        return True
    
    # Length difference > threshold bytes
    if abs(sig1["length"] - sig2["length"]) > threshold:
        return True
    
    # Different content
    if sig1["hash"] != sig2["hash"]:
        return True
    
    return False


def discover_params(
    url: str,
    wordlist: List[str] = None,
    cookie: str = None,
    proxy: str = None,
    threads: int = 10,
    headless: bool = False
) -> List[Dict]:
    """
    Discover hidden parameters by fuzzing and comparing responses.
    
    Args:
        url: Target URL (with or without existing params)
        wordlist: Custom wordlist (uses default if None)
        cookie: Session cookie
        proxy: Proxy URL
        threads: Concurrent threads
        headless: Use headless browser
        
    Returns:
        List of discovered parameters with details
    """
    console.print(f"\n[bold magenta][*] PARAMETER DISCOVERY[/bold magenta] -> [yellow]{url}[/yellow]")
    
    wordlist = wordlist or PARAM_WORDLIST
    log_info(f"Testing {len(wordlist)} parameter names...")
    
    session = TsurugiSession(cookie_string=cookie, proxy=proxy)
    
    parsed = urlparse(url)
    existing_params = parse_qs(parsed.query)
    
    # Get baseline response
    log_info("Getting baseline response...")
    baseline_resp = session.get(url, timeout=10)
    if not baseline_resp:
        log_error("Failed to get baseline response")
        return []
    
    baseline_sig = get_response_signature(baseline_resp)
    log_info(f"Baseline: {baseline_sig['status']} | {baseline_sig['length']} bytes")
    
    # Filter out params that already exist
    params_to_test = [p for p in wordlist if p not in existing_params]
    
    discovered = []
    tested = 0
    
    def test_param(param: str) -> Optional[Dict]:
        """Test a single parameter."""
        for value_type, value in TEST_VALUES.items():
            test_params = existing_params.copy()
            test_params[param] = [value]
            
            query_string = urlencode(test_params, doseq=True)
            test_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, query_string, parsed.fragment
            ))
            
            try:
                resp = session.get(test_url, timeout=5)
                if resp:
                    sig = get_response_signature(resp)
                    
                    if signatures_differ(baseline_sig, sig):
                        return {
                            "param": param,
                            "value_type": value_type,
                            "test_value": value,
                            "status_change": baseline_sig["status"] != sig["status"],
                            "length_diff": sig["length"] - baseline_sig["length"],
                            "content_change": baseline_sig["hash"] != sig["hash"],
                            "response_status": sig["status"],
                            "response_length": sig["length"]
                        }
            except:
                pass
        return None
    
    with Progress() as progress:
        task = progress.add_task("[cyan]Testing parameters...", total=len(params_to_test))
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(test_param, p): p for p in params_to_test}
            
            for future in as_completed(futures):
                param = futures[future]
                progress.advance(task)
                
                try:
                    result = future.result()
                    if result:
                        discovered.append(result)
                        console.print(f"  [green]✓[/green] Found: [bold]{result['param']}[/bold] ({result['value_type']})")
                except:
                    pass
    
    # Display results
    if discovered:
        console.print(f"\n[bold green]✓ Discovered {len(discovered)} hidden parameters![/bold green]")
        
        table = Table(title="Hidden Parameters", border_style="green")
        table.add_column("Parameter", style="bold")
        table.add_column("Type")
        table.add_column("Status Δ")
        table.add_column("Length Δ")
        table.add_column("Content Δ")
        
        for d in discovered:
            table.add_row(
                d["param"],
                d["value_type"],
                "✓" if d["status_change"] else "-",
                f"{d['length_diff']:+d}",
                "✓" if d["content_change"] else "-"
            )
        
        console.print(table)
        
        # Save to loot
        save_loot("params", url, {
            "discovered": discovered,
            "total_tested": len(params_to_test),
            "baseline": baseline_sig
        })
    else:
        log_info("No hidden parameters discovered")
    
    return discovered


def run_params_scan(url: str, cookie: str = None, proxy: str = None, 
                    threads: int = 10, headless: bool = False) -> List[Dict]:
    """Run parameter discovery scan."""
    return discover_params(url, cookie=cookie, proxy=proxy, threads=threads, headless=headless)
