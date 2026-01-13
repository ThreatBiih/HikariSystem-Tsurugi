# ═══════════════════════════════════════════════════════════════════════════════
#  HIKARI SYSTEM: TSURUGI v3.0
#  Offensive Web Scanner & Auto-Exploiter
#  Features: SQLi, XSS (confirmed), LFI, SSTI, Secrets, DOM XSS, Nuclei, Params
# ═══════════════════════════════════════════════════════════════════════════════

import typer
import os
import signal
import sys
from typing import Optional
from core.ui import console, print_banner
from modules.sqli import run_sqli_scan
from modules.recon import run_nmap_scan, analyze_services
from modules.lfi import run_lfi_scan
from modules.hunter import run_hunter_protocol
from modules.crawler import crawl_target, discover_api_endpoints
from modules.xss import run_xss_scan
from modules.ssti import run_ssti_scan
from modules.secrets import run_secrets_scan
from modules.params import run_params_scan
from modules.domxss import run_domxss_scan
from modules.nuclei import run_nuclei_scan
from modules.jwt_attack import run_jwt_attack
from modules.cors import run_cors_scan
from modules.headers import run_headers_scan
from modules.ssrf import run_ssrf_scan
from modules.fuzzer import run_fuzzer_scan
from modules.redirect import run_redirect_scan
from modules.auth_crawl import run_auth_crawl
from modules.graphql import run_graphql_scan, dump_schema
from core.waf import detect_and_suggest as run_waf_fingerprint
from modules.sqli_extractor import run_sqli_extraction
from modules.xss_exploiter import run_xss_exploit
from modules.lfi_exploiter import run_lfi_exploit
from modules.cve_intel import run_cve_lookup
from core.workflow import run_autopilot

# Load environment variables
from dotenv import load_dotenv
load_dotenv()

app = typer.Typer(help="TSURUGI v4.0 - Headless-First Offensive Web Scanner")

from core.oob import InteractshClient
from core.context import TsurugiContext

# Context instance (replaces global state dict)
ctx: TsurugiContext = None

def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully."""
    console.print("\n[yellow][!] Interrupted by user. Exiting...[/yellow]")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

@app.callback()
def main(
    cookie: Optional[str] = typer.Option(None, "--cookie", "-c", help="Session cookie (e.g., 'PHPSESSID=xyz')"),
    proxy: Optional[str] = typer.Option(None, "--proxy", "-p", help="Proxy URL (e.g., 'http://127.0.0.1:8080')"),
    proxy_file: Optional[str] = typer.Option(None, "--proxy-pool", help="File with proxy list for rotation"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose output"),
    oob: bool = typer.Option(False, "--oob", help="Enable OOB (Out-of-Band) Interaction for Blind detection"),
    heavy: bool = typer.Option(False, "--heavy", help="Enable Heavy Mode (Headless Browser) for SPA sites"),
    stealth: bool = typer.Option(False, "--stealth", "-s", help="Enable Stealth Mode (random delays, header rotation)"),
    cf_bypass: bool = typer.Option(False, "--cf-bypass", help="Enable Cloudflare bypass mode (auto-escalating)")
):
    """
    Set global options like cookies, proxy, and evasion modes.
    """
    global ctx
    
    # Create TsurugiContext with all options
    ctx = TsurugiContext(
        cookie=cookie,
        proxy=proxy,
        verbose=verbose,
        headless=heavy,
        stealth_mode=stealth,
        cf_bypass=cf_bypass
    )
    
    # Initialize stealth messaging
    if stealth:
        console.print("[cyan][*] Stealth Mode enabled: TLS rotation + random delays[/cyan]")
    
    # Show CF bypass status
    if cf_bypass:
        console.print("[cyan][*] Cloudflare Bypass Mode enabled (curl_cffi TLS stealth)[/cyan]")
    
    # Initialize OOB client if requested
    if oob:
        console.print("[blue][*] Initializing OOB Interaction (Interactsh)...[/blue]")
        client = InteractshClient()
        if client.register():
            ctx.oob_client = client
        else:
            console.print("[red][!] OOB Registration Failed. Continuing without it.[/red]")

@app.command(name="auth-crawl")
def auth_crawl_cmd(start_url: str = typer.Argument(..., help="URL to start crawling from (after login)"),
                   login_url: str = typer.Option(..., "--login", "-l", help="Login form URL"),
                   username: str = typer.Option(..., "--user", "-u", help="Username"),
                   password: str = typer.Option(..., "--pass", "-p", help="Password"),
                   user_field: str = typer.Option("username", "--user-field", help="Username field name"),
                   pass_field: str = typer.Option("password", "--pass-field", help="Password field name"),
                   success: str = typer.Option(None, "--success", help="Text that appears after successful login"),
                   logout: str = typer.Option(None, "--logout", help="Text that indicates session expired"),
                   depth: int = typer.Option(3, "--depth", "-d", help="Max crawl depth"),
                   pages: int = typer.Option(100, "--pages", help="Max pages to crawl")):
    """
    [AUTH] Session-Aware Authenticated Crawler.
    Logs in automatically, maintains session, re-logins on expiry, extracts CSRF tokens.
    """
    print_banner()
    run_auth_crawl(
        start_url, login_url, username, password,
        username_field=user_field, password_field=pass_field,
        success_indicator=success, logout_indicator=logout,
        depth=depth, max_pages=pages,
        cookie=ctx.cookie, proxy=ctx.proxy
    )

@app.command()
def attack(
    url: str = typer.Argument(..., help="Target URL with parameters (http://site.com?id=1)"),
    sqli: bool = typer.Option(False, "--sqli", help="Run SQL Injection scan"),
    xss: bool = typer.Option(False, "--xss", help="Run Reflected XSS scan"),
    lfi: bool = typer.Option(False, "--lfi", help="Run LFI scan"),
    ssti: bool = typer.Option(False, "--ssti", help="Run SSTI scan"),
    all_checks: bool = typer.Option(False, "--all", "-a", help="Run ALL scans"),
    confirm: bool = typer.Option(False, "--confirm", "-C", help="Confirm XSS in headless browser")
):
    """
    Multi-Vector Attack Mode: SQLi, XSS, LFI, SSTI.
    Default: SQLi only (if no flags provided).
    """
    print_banner()

    if all_checks:
        sqli = xss = lfi = ssti = True
    
    # Default to SQLi if no specific vector is chosen
    if not (sqli or xss or lfi or ssti):
        sqli = True

    if sqli:
        console.print("[bold yellow][*] Mode: SQL Injection[/bold yellow]")
        run_sqli_scan(ctx, url)

    if xss:
        console.print("\n[bold yellow][*] Mode: Reflected XSS[/bold yellow]")
        run_xss_scan(ctx, url, confirm=confirm)

    if lfi:
        console.print("\n[bold yellow][*] Mode: LFI[/bold yellow]")
        run_lfi_scan(ctx, url)

    if ssti:
        console.print("\n[bold yellow][*] Mode: SSTI[/bold yellow]")
        run_ssti_scan(ctx, url)

@app.command()
def lfi(url: str = typer.Argument(..., help="Target URL with parameters")):
    """
    LFI Scanner: Fuzzes parameters for Local File Inclusion (LFI).
    """
    print_banner()
    run_lfi_scan(ctx, url)


@app.command(name="sqli-dump")
def sqli_dump(url: str = typer.Argument(..., help="Target URL with SQLi vulnerability"),
              param: str = typer.Option(None, "--param", "-P", help="Vulnerable parameter"),
              tables_only: bool = typer.Option(False, "--tables", "-T", help="Only list tables"),
              dump_table: str = typer.Option(None, "--dump", "-D", help="Table to dump")):
    """
    [EXPLOIT] SQLi Data Extraction: Extract databases, tables, columns, and data.
    UNION-based and Blind extraction. No more 'run sqlmap'.
    """
    print_banner()
    run_sqli_extraction(url, param=param, cookie=ctx.cookie, proxy=ctx.proxy,
                        tables_only=tables_only, dump_table=dump_table)


@app.command(name="xss-exploit")
def xss_exploit_cmd(callback: str = typer.Option("http://YOUR_IP:8888", "--callback", "-C", help="Callback server URL"),
                    payload_type: str = typer.Option("all", "--type", "-t", help="cookie, keylogger, session, form, polyglot, all"),
                    encode: str = typer.Option(None, "--encode", "-e", help="Encode: base64, url, unicode, html"),
                    save_server: bool = typer.Option(False, "--save-server", help="Save callback server script")):
    """
    [EXPLOIT] XSS Payload Generator: Create weaponized XSS payloads.
    Cookie stealer, keylogger, session hijacker, form grabber.
    """
    print_banner()
    run_xss_exploit(callback_url=callback, payload_type=payload_type,
                    encode=encode, save_server=save_server)


@app.command(name="lfi-exploit")
def lfi_exploit_cmd(url: str = typer.Argument(..., help="Target URL with LFI vulnerability"),
                    param: str = typer.Option(None, "--param", "-P", help="Vulnerable parameter"),
                    read_file: str = typer.Option(None, "--file", "-f", help="Specific file to read"),
                    test_rce: bool = typer.Option(True, "--rce/--no-rce", help="Test for RCE possibilities")):
    """
    [EXPLOIT] LFI Exploitation: Read files and escalate to RCE.
    Auto-reads /etc/passwd, tests log poisoning, PHP wrappers.
    """
    print_banner()
    run_lfi_exploit(url, param=param, cookie=ctx.cookie, proxy=ctx.proxy,
                    read_file=read_file, test_rce=test_rce)

@app.command()
def xss(url: str = typer.Argument(..., help="Target URL with parameters"),
        confirm: bool = typer.Option(False, "--confirm", "-C", help="Confirm XSS in headless browser (zero false positives)")):
    """
    XSS Scanner: Fuzzes parameters for Reflected XSS.
    Use --confirm to verify XSS executes in a real browser.
    """
    print_banner()
    run_xss_scan(ctx, url, confirm=confirm)

@app.command()
def ssti(url: str = typer.Argument(..., help="Target URL with parameters"),
         shell: bool = typer.Option(False, "--shell", "-S", help="Spawn interactive shell on RCE confirmation"),
         exploit: bool = typer.Option(True, "--exploit/--no-exploit", help="Auto-attempt RCE")):
    """
    [WEAPONIZED] SSTI Scanner: Detects and EXPLOITS Server-Side Template Injection.
    Supports: Jinja2, Twig, Freemarker, Velocity, SpEL, OGNL, Smarty, Mako.
    Auto-RCE with interactive shell (--shell).
    """
    print_banner()
    run_ssti_scan(url, cookie=ctx.cookie, proxy=ctx.proxy, auto_exploit=exploit, shell=shell)

@app.command()
def secrets(url: str = typer.Argument(..., help="Target URL to scan for secrets"),
            verify: bool = typer.Option(False, "--verify", "-V", help="Actively verify found secrets (calls APIs)")):
    """
    Secrets Scanner: Detects API keys, tokens, credentials (AWS, Stripe, GitHub, JWT, etc).
    Use --verify to check if secrets are valid by calling their respective APIs.
    """
    print_banner()
    run_secrets_scan(url, cookie=ctx.cookie, proxy=ctx.proxy, headless=ctx.headless, verify=verify)


@app.command()
def params(url: str = typer.Argument(..., help="Target URL to discover hidden parameters"),
           threads: int = typer.Option(10, "-t", "--threads", help="Concurrent threads")):
    """
    Parameter Discovery: Finds hidden parameters in endpoints.
    Tests 100+ common param names (debug, admin, token, etc).
    """
    print_banner()
    run_params_scan(url, cookie=ctx.cookie, proxy=ctx.proxy, threads=threads, headless=ctx.headless)


@app.command()
def domxss(url: str = typer.Argument(..., help="Target URL to analyze for DOM XSS")):
    """
    DOM XSS Analysis: Static analysis of JavaScript for dangerous sinks.
    Detects innerHTML, eval, document.write, location, jQuery methods, etc.
    """
    print_banner()
    run_domxss_scan(url, cookie=ctx.cookie, proxy=ctx.proxy, headless=ctx.headless)


@app.command()
def nuclei(target: str = typer.Argument(..., help="Target URL or domain"),
           templates: str = typer.Option("cves,exposures,misconfiguration", "-t", "--templates", help="Template categories"),
           severity: str = typer.Option("critical,high,medium", "-s", "--severity", help="Severity filter"),
           threads: int = typer.Option(25, "-c", "--threads", help="Concurrent threads")):
    """
    Nuclei Scanner: Use ProjectDiscovery's 6000+ templates to find CVEs, misconfigs, exposures.
    Requires 'nuclei' installed (go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest).
    """
    print_banner()
    run_nuclei_scan(target, templates=templates, severity=severity, threads=threads)


@app.command()
def jwt(token: str = typer.Argument(..., help="JWT token to analyze"),
        decode: bool = typer.Option(False, "--decode", "-d", help="Only decode, no attacks"),
        crack: bool = typer.Option(False, "--crack", "-c", help="Bruteforce weak secret"),
        none: bool = typer.Option(False, "--none", "-n", help="Try None algorithm attack"),
        tamper: str = typer.Option(None, "--tamper", "-t", help="Modify claims (format: admin=true,role=admin)"),
        secret: str = typer.Option(None, "--secret", "-s", help="Known secret for verification/tampering"),
        public_key: str = typer.Option(None, "--public-key", "-k", help="Public key for algorithm confusion")):
    """
    JWT Attack Module: Analyze and exploit JWT tokens.
    Supports: Decode, None Algorithm, Weak Secret Bruteforce, Algorithm Confusion, Claim Tampering.
    """
    print_banner()
    run_jwt_attack(
        token,
        decode_only=decode,
        crack=crack,
        attack_none=none,
        tamper=tamper,
        secret=secret,
        public_key=public_key
    )


@app.command()
def cors(url: str = typer.Argument(..., help="Target URL (API endpoint preferred)")):
    """
    CORS Misconfiguration Scanner: Detects insecure cross-origin configurations.
    Tests: Origin reflection, Null origin, Subdomain bypass, Wildcard, Protocol downgrade.
    """
    print_banner()
    run_cors_scan(url, cookie=ctx.cookie, proxy=ctx.proxy)


@app.command()
def headers(url: str = typer.Argument(..., help="Target URL to scan")):
    """
    Security Headers Scanner: Checks for missing security headers and info disclosure.
    Tests: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, and more.
    """
    print_banner()
    run_headers_scan(url, proxy=ctx.proxy)


@app.command()
def waf(url: str = typer.Argument(..., help="Target URL to fingerprint")):
    """
    WAF Fingerprinting: Identify WAF vendor and get bypass suggestions.
    Detects: Cloudflare, Akamai, AWS WAF, ModSecurity, Imperva, F5, and more.
    """
    print_banner()
    from core.requester import TsurugiSession
    requester = TsurugiSession(cookie_string=ctx.cookie, proxy=ctx.proxy, stealth=True)
    run_waf_fingerprint(url, requester)


@app.command()
def ssrf(url: str = typer.Argument(..., help="Target URL"),
         oob: bool = typer.Option(False, "--oob", "-o", help="Enable Out-of-Band (Interactsh)")):
    """
    SSRF Scanner: Detects Server-Side Request Forgery vulnerabilities.
    Supports Blind SSRF via Interactsh (requires --oob).
    """
    print_banner()
    
    oob_client = None
    if oob:
        oob_client = InteractshClient()
        if not oob_client.register():
             from core.ui import log_error
             log_error("Failed to register OOB client. Continuing without OOB.")
             oob_client = None

    run_ssrf_scan(url, cookie=ctx.cookie, proxy=ctx.proxy, oob_client=oob_client)


@app.command()
def fuzz(url: str = typer.Argument(..., help="Target URL"),
         wordlist: str = typer.Option(None, "--wordlist", "-w", help="Custom wordlist path (default: built-in list)"),
         threads: int = typer.Option(50, "--threads", "-t", help="Threads"),
         extensions: bool = typer.Option(False, "--ext", "-x", help="Try extensions (.php, .bak, etc)")):
    """
    Advanced Directory Fuzzer: Finds hidden paths, admin panels, and backups.
    Auto-calibrates for 404 responses.
    """
    print_banner()
    run_fuzzer_scan(url, wordlist_path=wordlist, threads=threads, extensions=extensions, cookie=ctx.cookie, proxy=ctx.proxy)


@app.command()
def redirect(url: str = typer.Argument(..., help="Target URL (e.g., https://site.com/login?next=/)")):
    """
    Open Redirect Scanner: Detects Unvalidated Redirects and Forwards.
    """
    print_banner()
    run_redirect_scan(url, cookie=ctx.cookie, proxy=ctx.proxy)


@app.command()
def diff(url: str = typer.Argument(..., help="Base URL to test"),
         payload: str = typer.Option(..., "--payload", "-p", help="Payload to inject"),
         param: str = typer.Option(None, "--param", help="Parameter to inject into (if not in URL)")):
    """
    [DIFF] Differential Analysis: Compare baseline vs payload response.
    Detects subtle differences for blind vulnerability detection.
    """
    import time
    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
    from core.diff_engine import DiffEngine
    from core.requester import TsurugiSession
    
    print_banner()
    console.print(f"\n[bold cyan][DIFF] DIFFERENTIAL RESPONSE ANALYSIS[/bold cyan]")
    
    requester = TsurugiSession(cookie_string=ctx.cookie, proxy=ctx.proxy)
    diff_engine = DiffEngine()
    
    # Baseline request
    console.print("[*] Fetching baseline...")
    start = time.time()
    base_resp = requester.get(url)
    base_time = time.time() - start
    
    if not base_resp:
        console.print("[red]Failed to get baseline response[/red]")
        return
    
    diff_engine.add_baseline(base_resp, base_time)
    console.print(f"[dim]Baseline: {base_resp.status_code}, {len(base_resp.content)} bytes, {base_time:.2f}s[/dim]")
    
    # Build payload URL
    if param:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [payload]
        query = urlencode(params, doseq=True)
        payload_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query, parsed.fragment))
    else:
        payload_url = url.replace("FUZZ", payload) if "FUZZ" in url else url + payload
    
    # Payload request
    console.print(f"[*] Testing payload: {payload[:50]}...")
    start = time.time()
    test_resp = requester.get(payload_url)
    test_time = time.time() - start
    
    if not test_resp:
        console.print("[red]Failed to get payload response[/red]")
        return
    
    console.print(f"[dim]Payload: {test_resp.status_code}, {len(test_resp.content)} bytes, {test_time:.2f}s[/dim]")
    
    # Compare
    result = diff_engine.compare(test_resp, test_time)
    
    if result.is_different:
        console.print(Panel(
            f"Confidence: {result.confidence:.1%}\n"
            f"Differences: {', '.join(result.differences)}\n"
            f"Length Δ: {result.length_diff} bytes\n"
            f"Similarity: {result.similarity_ratio:.1%}\n"
            f"Timing Anomaly: {'Yes' if result.timing_anomaly else 'No'}",
            title="[!] DIFFERENCES DETECTED",
            border_style="yellow"
        ))
    else:
        console.print("[green]✓ No significant differences detected[/green]")


@app.command()
def hunter(domain: str = typer.Argument(..., help="Target Domain (e.g., target.com)"),
           full: bool = typer.Option(False, "--full", "-f", help="Scan for Medium/Low severity as well")):
    """
    Hunter Protocol: Orchestrates external tools (Subfinder -> Nuclei) 
    for automated reconnaissance and vulnerability scanning.
    Requires 'subfinder' and 'nuclei' installed in PATH.
    """
    print_banner()
    run_hunter_protocol(domain, full)

@app.command()
def crawl(url: str = typer.Argument(..., help="Start URL to crawl"),
          depth: int = typer.Option(2, help="Crawl depth"),
          fast: bool = typer.Option(False, "--fast", "-f", help="Fast mode (curl_cffi, no JS rendering)")):
    """
    [HEADLESS-FIRST] Crawler: Spiders the website with full JS rendering.
    DEFAULT: Playwright (SPAs, React, Vue, Angular).
    --fast: curl_cffi (TLS stealth, no JS).
    Detects DOM sinks, API endpoints, forms, and secrets.
    """
    print_banner()
    findings = crawl_target(url, depth, cookie=ctx.cookie, proxy=ctx.proxy, fast=fast)


@app.command()
def api(url: str = typer.Argument(..., help="Target URL to discover API endpoints"),
        fast: bool = typer.Option(False, "--fast", "-f", help="Fast mode (no JS rendering)")):
    """
    API Discovery: Find API endpoints from JavaScript analysis, common paths, and subdomains.
    Output can be used with 'cors' or 'graphql' commands.
    """
    print_banner()
    discover_api_endpoints(url, cookie=ctx.cookie, proxy=ctx.proxy, fast=fast)


@app.command()
def graphql(url: str = typer.Argument(..., help="GraphQL endpoint or base URL"),
            deep: bool = typer.Option(False, "--deep", "-D", help="Enable deep testing (injection)"),
            dump: bool = typer.Option(False, "--dump", help="Dump schema to JSON file"),
            output: str = typer.Option(None, "--output", "-o", help="Output file for schema dump")):
    """
    GraphQL Scanner: Comprehensive GraphQL security testing.
    Tests: Introspection, Batching DoS, Field enumeration, Injection.
    Use --dump to export schema, --deep for injection testing.
    """
    print_banner()
    if dump:
        dump_schema(url, cookie=ctx.cookie, proxy=ctx.proxy, output_file=output or "graphql_schema.json")
    else:
        run_graphql_scan(url, cookie=ctx.cookie, proxy=ctx.proxy, deep=deep)

@app.command()
def recon(target: str = typer.Argument(..., help="Target IP or Domain"),
          auto_attack: bool = typer.Option(False, "--auto", "-a", help="Automatically attack detected web services")):
    """
    Recon Mode: Runs Nmap Service Scan and identifies attack surfaces.
    """
    print_banner()
    services = run_nmap_scan(target)
    
    if not services:
        return

    web_targets = analyze_services(target, services)
    
    if web_targets:
        if auto_attack:
            console.print("\n[bold red][*] AUTO-ATTACK MODE ENGAGED[/bold red]")
            for url in web_targets:
                console.print(f"Scanning base: {url} (Note: Full SQLi scan requires parameterized URLs)")
        else:
            console.print("\n[blue]Found Web Targets:[/blue]")
            for t in web_targets:
                console.print(f"  - {t}")
            console.print("\nRun [bold]tsurugi attack <url_with_params>[/bold] to exploit.")

@app.command()
def mass_check(
    list_file: str = typer.Argument(..., help="File with list of URLs"),
    threads: int = typer.Option(10, "--threads", "-t", help="Number of concurrent threads"),
    module: str = typer.Option("sqli", "--module", "-m", help="Module to run: sqli, lfi, xss, ssti")
):
    """
    Mass Scanner: multithreaded scanning of a URL list.
    """
    print_banner()
    if not os.path.exists(list_file):
        console.print(f"[red][!] File not found: {list_file}[/red]")
        return

    with open(list_file, 'r') as f:
        urls = [line.strip() for line in f if line.strip()]

    # Filter URLs that have parameters if using injection modules
    if module in ["sqli", "lfi", "xss", "ssti"]:
        urls = [u for u in urls if "?" in u and "=" in u]
    
    if not urls:
        console.print("[yellow][!] No suitable URLs found in list.[/yellow]")
        return

    console.print(f"[bold cyan][*] Starting Mass Scan on {len(urls)} targets with {threads} threads...[/bold cyan]")

    from concurrent.futures import ThreadPoolExecutor, as_completed
    
    # Mapper for modules
    scanner_map = {
        "sqli": run_sqli_scan,
        "lfi": run_lfi_scan,
        "xss": run_xss_scan,
        "ssti": run_ssti_scan,
    }
    
    scan_func = scanner_map.get(module)
    if not scan_func:
        console.print(f"[red][!] Unknown module: {module}. Available: sqli, lfi, xss, ssti[/red]")
        return

    # Track results
    results = {"success": 0, "error": 0, "found": 0}
    
    # PHASE 1: Async pre-filter (check which URLs are alive)
    console.print("[cyan][*] Phase 1: Async pre-filtering URLs...[/cyan]")
    from core.async_requester import run_async_batch
    
    alive_urls = []
    async_results = run_async_batch(urls, max_concurrent=threads)
    for resp in async_results:
        if resp.status_code and resp.status_code < 500 and not resp.error:
            alive_urls.append(resp.url)
    
    console.print(f"[green][+] {len(alive_urls)}/{len(urls)} URLs responding[/green]")
    
    if not alive_urls:
        console.print("[yellow]No alive URLs to scan.[/yellow]")
        return
    
    # PHASE 2: Deep scan with selected module
    console.print(f"[cyan][*] Phase 2: Deep scanning with {module}...[/cyan]")
    
    # Wrapper with exception handling
    def worker(url):
        try:
            # Modules refactored to use ctx: sqli, lfi, xss, ssti
            if module in ["sqli", "lfi", "xss", "ssti"]:
                found = scan_func(ctx, url)
            else:
                # Legacy modules still use old signature
                found = scan_func(url, cookie=ctx.cookie, proxy=ctx.proxy, oob_client=ctx.oob_client, headless=ctx.headless)
            return ("success", found)
        except Exception as e:
            if ctx.verbose:
                console.print(f"[dim][!] Error on {url}: {e}[/dim]")
            return ("error", False)

    with ThreadPoolExecutor(max_workers=min(threads, len(alive_urls))) as executor:
        futures = {executor.submit(worker, url): url for url in alive_urls}
        
        for future in as_completed(futures):
            try:
                status, found = future.result()
                results[status] += 1
                if found:
                    results["found"] += 1
            except Exception as e:
                results["error"] += 1
        
    console.print(f"\n[bold green][+] Mass Scan Completed![/bold green]")
    console.print(f"    Scanned: {results['success']} | Errors: {results['error']} | Vulnerabilities: {results['found']}")

@app.command()
def report():
    """
    Generate an HTML report from collected loot.
    """
    from core.reporter import generate_report
    print_banner()
    console.print("[blue][*] Generating Report...[/blue]")
    filename = generate_report()
    if filename:
        console.print(f"[bold green][+] Report generated: {filename}[/bold green]")
    else:
        console.print("[yellow][!] No findings to report.[/yellow]")

@app.command()
def cve(keyword: str = typer.Argument(..., help="Technology to search (e.g., wordpress, apache)"),
        version: str = typer.Option(None, "--version", "-v", help="Specific version"),
        limit: int = typer.Option(10, "--limit", "-l", help="Max results"),
        severity: str = typer.Option(None, "--severity", "-s", help="Filter: CRITICAL, HIGH, MEDIUM, LOW")):
    """
    CVE Intelligence: Search for CVEs by technology/version.
    Queries NVD database and caches results.
    Example: tsurugi cve wordpress --version 6.0
    """
    print_banner()
    run_cve_lookup(keyword, version, limit, severity)

@app.command()
def autopilot(target: str = typer.Argument(..., help="Target domain (e.g., target.com)"),
              scope: str = typer.Option(None, "--scope", "-s", help="Scope pattern (e.g., *.target.com)"),
              resume: str = typer.Option(None, "--resume", "-r", help="Resume workflow by ID")):
    """
    Bug Bounty Autopilot: Automated recon -> scan -> report workflow.
    Runs: Subdomain Enum -> Live Detection -> Tech Detect -> CVE Intel -> Vuln Scan -> Report.
    Use --resume to continue a previous workflow.
    """
    print_banner()
    run_autopilot(target, scope, resume)

if __name__ == "__main__":
    app()