# HikariSystem Tsurugi/modules/fuzzer.py
"""
ADVANCED FUZZER MODULE
Multi-threaded directory and file brute-forcing with smart detection.
"""
import concurrent.futures
import time
from typing import List, Set
from urllib.parse import urljoin
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeRemainingColumn
from rich.panel import Panel
from core.ui import console, log_info, log_success, log_warning, log_error
from core.logger import save_loot
from core.requester import TsurugiSession

# Optimized Built-in Wordlist (Critical paths only)
BUILTIN_WORDLIST = [
    # Admin Panels
    "admin", "administrator", "admin_panel", "cpanel", "controlpanel",
    "login", "dashboard", "manage", "manager", "backend",
    "hf-admin", "wp-admin", "phpmyadmin", "admin.php", "login.php",
    # Configs & Secrets
    ".env", ".git/HEAD", ".vscode/settings.json", "config.php", "config.json",
    "web.config", ".htaccess", "docker-compose.yml", "id_rsa",
    "backup.sql", "database.sql", "dump.sql", "data.sql",
    "settings.py", "secrets.py", "appsettings.json",
    # Backups
    "index.php.bak", "index.php.old", "index.html.bak", "config.php.bak",
    "backup.zip", "site.zip", "www.zip", "backup.tar.gz",
    # API & Dev
    "api", "api/v1", "api/v2", "swagger.json", "openapi.json",
    "dev", "test", "staging", "server-status", "info.php",
    # Framework specifics
    "actuator/health", "actuator/env", "console", "telescope",
]

# Extensions to brute force
EXTENSIONS = [".php", ".bak", ".old", ".txt", ".json", ".zip", ".sql"]

def calibrate_404(url: str, requester: TsurugiSession) -> int:
    """Detects how the server handles 404s (Status, Content Length)."""
    random_path = f"tsurugi_check_{int(time.time())}"
    check_url = urljoin(url, random_path)
    
    try:
        resp = requester.get(check_url, timeout=5)
        if resp:
            # If server returns 200 for random path, it's a wildcard
            if resp.status_code == 200:
                log_warning("Server returns 200 OK for non-existent pages (Wildcard detected). using content analysis.")
                return len(resp.content)
            return -1 # Standard 404 behavior
    except:
        pass
    return -1

def fuzz_path(url: str, path: str, requester: TsurugiSession, bad_length: int = -1) -> dict:
    """Test a single path."""
    target_url = urljoin(url, path)
    if not target_url.endswith("/") and "." not in path:
        target_url += "/" # Ensure directory structure if no extension
        
    try:
        resp = requester.get(target_url, allow_redirects=False, timeout=5)
        if not resp:
            return None
            
        code = resp.status_code
        size = len(resp.content)
        
        # Filtering logic
        if code == 404:
            return None
            
        # Filter wildcard soft-404s by size
        if bad_length != -1 and abs(size - bad_length) < 50:
            return None
            
        if code in [200, 301, 302, 401, 403, 405, 429, 500, 502, 503]:
            return {
                "url": target_url,
                "status": code,
                "size": size,
                "redirect": resp.headers.get("Location")
            }
    except:
        pass
    return None

def run_fuzzer_scan(url: str, wordlist_path: str = None, threads: int = 20, extensions: bool = False, cookie: str = None, proxy: str = None):
    """
    Orchestrate the fuzzing scan.
    """
    console.print(f"\n[bold magenta][*] ADVANCED DIRECTORY FUZZER[/bold magenta] -> [yellow]{url}[/yellow]")
    if not url.endswith("/"):
        url += "/"
        
    requester = TsurugiSession(cookie_string=cookie, proxy=proxy)
    
    # 1. Calibration
    log_info("Calibrating 404 behavior...")
    bad_length = calibrate_404(url, requester)
    
    # 2. Build Wordlist
    words = BUILTIN_WORDLIST.copy()
    if wordlist_path:
        try:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                custom_words = [line.strip() for line in f if line.strip()]
            log_info(f"Loaded {len(custom_words)} words from custom wordlist.")
            words = custom_words # Override or extend? Let's use custom if provided, mostly.
        except Exception as e:
            log_error(f"Failed to load wordlist: {e}. Using builtin.")
            
    # Add extensions if requested
    final_queue = set(words)
    if extensions:
        log_info("Appending extensions (.php, .bak, .zip, etc)...")
        ext_words = set()
        for w in words:
            if "." not in w: # Only add extensions to non-files
                for ext in EXTENSIONS:
                    ext_words.add(f"{w}{ext}")
        final_queue.update(ext_words)
        
    wordlist = list(final_queue)
    log_info(f"Starting Fuzzing with {len(wordlist)} paths using {threads} threads...")
    
    findings = []
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeRemainingColumn(),
    ) as progress:
        task = progress.add_task("[cyan]Fuzzing...", total=len(wordlist))
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            # Submit all tasks
            future_to_path = {executor.submit(fuzz_path, url, path, requester, bad_length): path for path in wordlist}
            
            for future in concurrent.futures.as_completed(future_to_path):
                path = future_to_path[future]
                progress.update(task, advance=1)
                
                try:
                    result = future.result()
                    if result:
                        color = "green" if result["status"] == 200 else "yellow" if result["status"] in [301, 302] else "red"
                        
                        msg = f"[{color}]{result['status']}[/{color}] {result['url']} (Size: {result['size']})"
                        if result['redirect']:
                            msg += f" -> {result['redirect']}"
                            
                        # Instant print for findings
                        progress.console.print(msg)
                        findings.append(result)
                        
                except Exception as e:
                    pass

    # Report
    if findings:
        console.print(f"\n[bold green][+] Found {len(findings)} paths![/bold green]")
        
        # Highlight interesting findings
        critical = [f for f in findings if f['status'] == 200 and ("admin" in f['url'] or "config" in f['url'] or ".env" in f['url'] or "hf-admin" in f['url'])]
        
        if critical:
            console.print(Panel(
                "\n".join([f"{f['url']} ({f['status']})" for f in critical]),
                title="[bold red]🚨 CRITICAL FINDINGS[/bold red]",
                border_style="red"
            ))
        
        save_loot("fuzzer", url, {"findings": findings})
    else:
        console.print("[yellow]No paths found (Try a bigger wordlist).[/yellow]")
