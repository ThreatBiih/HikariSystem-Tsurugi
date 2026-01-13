# HikariSystem Tsurugi/modules/cors.py
"""
CORS MISCONFIGURATION SCANNER
Detects insecure CORS configurations that allow cross-origin attacks
"""
import re
from typing import Dict, List, Optional
from urllib.parse import urlparse
from core.ui import console, log_info, log_success, log_warning, log_error
from core.logger import save_loot
from core.requester import TsurugiSession
from rich.panel import Panel
from rich.table import Table

# Test origins for different attack scenarios
def generate_test_origins(target_domain: str) -> List[Dict]:
    """Generate test origins to check for CORS misconfigurations."""
    base_domain = target_domain.replace("www.", "")
    
    return [
        # 1. Arbitrary Origin (Critical)
        {
            "origin": "https://evil.com",
            "name": "Arbitrary Origin",
            "severity": "CRITICAL",
            "description": "Accepts any external origin"
        },
        # 2. Null Origin (High)
        {
            "origin": "null",
            "name": "Null Origin",
            "severity": "HIGH",
            "description": "Accepts null origin (sandboxed iframes, file://)"
        },
        # 3. Subdomain with evil prefix
        {
            "origin": f"https://evil.{base_domain}",
            "name": "Subdomain Prefix",
            "severity": "HIGH",
            "description": "Accepts attacker-controlled subdomain"
        },
        # 4. Subdomain with evil suffix
        {
            "origin": f"https://{base_domain}.evil.com",
            "name": "Domain Suffix",
            "severity": "HIGH",
            "description": "Weak regex allows domain suffix bypass"
        },
        # 5. Protocol downgrade (HTTP on HTTPS)
        {
            "origin": f"http://{base_domain}",
            "name": "Protocol Downgrade",
            "severity": "MEDIUM",
            "description": "Accepts HTTP origin on HTTPS site"
        },
        # 6. Underscore bypass
        {
            "origin": f"https://{base_domain}_.evil.com",
            "name": "Underscore Bypass",
            "severity": "HIGH",
            "description": "Underscore regex bypass"
        },
        # 7. Local origins
        {
            "origin": "http://localhost",
            "name": "Localhost",
            "severity": "MEDIUM",
            "description": "Accepts localhost origin"
        },
        {
            "origin": "http://127.0.0.1",
            "name": "Loopback IP",
            "severity": "MEDIUM",
            "description": "Accepts loopback IP"
        },
    ]


def check_cors(url: str, origin: str, cookie: str = None, proxy: str = None) -> Dict:
    """
    Send request with Origin header and analyze CORS response.
    
    Returns:
        dict with CORS headers and analysis
    """
    headers = {
        "Origin": origin,
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "*/*",
    }
    
    # Use TsurugiSession for TLS stealth
    session = TsurugiSession(cookie_string=cookie, proxy=proxy)
    
    try:
        # Send request with Origin header
        resp = session.get(url, headers=headers, timeout=10, allow_redirects=False)
        
        if resp is None:
            return {"error": "Request failed"}
        
        # Extract CORS headers
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()
        acam = resp.headers.get("Access-Control-Allow-Methods", "")
        acah = resp.headers.get("Access-Control-Allow-Headers", "")
        aceh = resp.headers.get("Access-Control-Expose-Headers", "")
        
        return {
            "status_code": resp.status_code,
            "acao": acao,  # Access-Control-Allow-Origin
            "acac": acac,  # Access-Control-Allow-Credentials
            "acam": acam,  # Access-Control-Allow-Methods
            "acah": acah,  # Access-Control-Allow-Headers
            "aceh": aceh,  # Access-Control-Expose-Headers
            "origin_sent": origin,
            "reflected": acao == origin,
            "wildcard": acao == "*",
            "credentials": acac == "true",
        }
        
    except Exception as e:
        return {"error": str(e)}


def analyze_cors_response(result: Dict, test_info: Dict) -> Optional[Dict]:
    """
    Analyze CORS response for vulnerabilities.
    
    Returns:
        Finding dict if vulnerable, None otherwise
    """
    if "error" in result:
        return None
    
    acao = result.get("acao", "")
    credentials = result.get("credentials", False)
    origin_sent = result.get("origin_sent", "")
    
    # No CORS headers = not exploitable via CORS
    if not acao:
        return None
    
    finding = None
    
    # Critical: Origin reflection with credentials
    if result["reflected"] and credentials:
        finding = {
            "vulnerability": f"{test_info['name']} + Credentials",
            "severity": "CRITICAL",
            "description": f"Origin '{origin_sent}' reflected with credentials allowed",
            "impact": "Attacker can steal authenticated user data cross-origin",
            "acao": acao,
            "acac": "true",
        }
    
    # High: Origin reflection without credentials
    elif result["reflected"]:
        finding = {
            "vulnerability": test_info["name"],
            "severity": test_info["severity"],
            "description": test_info["description"],
            "impact": "Attacker can read responses cross-origin (non-authenticated)",
            "acao": acao,
            "acac": "false",
        }
    
    # Critical: Wildcard with credentials (misconfigured, shouldn't work but check)
    elif result["wildcard"] and credentials:
        finding = {
            "vulnerability": "Wildcard + Credentials (Misconfigured)",
            "severity": "CRITICAL",
            "description": "ACAO: * with credentials (browser ignores but indicates bad config)",
            "impact": "Misconfigured server, may have other issues",
            "acao": "*",
            "acac": "true",
        }
    
    # Medium: Wildcard without credentials (common, less severe)
    elif result["wildcard"]:
        finding = {
            "vulnerability": "Wildcard Origin",
            "severity": "LOW",
            "description": "Allows any origin but no credentials",
            "impact": "Public API, low risk unless sensitive data exposed",
            "acao": "*",
            "acac": "false",
        }
    
    return finding


def run_cors_scan(url: str, cookie: str = None, proxy: str = None) -> List[Dict]:
    """
    Run comprehensive CORS misconfiguration scan.
    
    Args:
        url: Target URL to test
        cookie: Session cookie
        proxy: Proxy URL
        
    Returns:
        List of findings
    """
    console.print(f"\n[bold magenta][*] CORS MISCONFIGURATION SCANNER[/bold magenta] -> [yellow]{url}[/yellow]")
    
    # Parse target domain
    parsed = urlparse(url)
    target_domain = parsed.netloc
    
    if not target_domain:
        log_error("Invalid URL")
        return []
    
    # Generate test origins
    test_origins = generate_test_origins(target_domain)
    
    log_info(f"Testing {len(test_origins)} origin configurations...")
    
    findings = []
    
    # First, check if CORS is even present
    log_info("Checking baseline CORS configuration...")
    baseline = check_cors(url, f"https://{target_domain}", cookie, proxy)
    
    if "error" in baseline:
        log_error(f"Request failed: {baseline['error']}")
        return []
    
    if not baseline.get("acao"):
        log_info("No CORS headers present on this endpoint")
        console.print("[dim]This endpoint doesn't return CORS headers. Try an API endpoint.[/dim]")
        return []
    
    console.print(f"[cyan]Baseline ACAO: {baseline.get('acao')}[/cyan]")
    console.print(f"[cyan]Credentials: {baseline.get('acac', 'not set')}[/cyan]")
    
    # Test each origin
    for test in test_origins:
        result = check_cors(url, test["origin"], cookie, proxy)
        finding = analyze_cors_response(result, test)
        
        if finding:
            findings.append(finding)
            
            sev = finding["severity"]
            if sev == "CRITICAL":
                console.print(f"  [bold red]✗ {finding['vulnerability']}[/bold red]")
            elif sev == "HIGH":
                console.print(f"  [red]✗ {finding['vulnerability']}[/red]")
            elif sev == "MEDIUM":
                console.print(f"  [yellow]! {finding['vulnerability']}[/yellow]")
            else:
                console.print(f"  [dim]- {finding['vulnerability']}[/dim]")
    
    # Display results
    if findings:
        # Sort by severity
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        findings.sort(key=lambda x: severity_order.get(x["severity"], 4))
        
        critical = [f for f in findings if f["severity"] == "CRITICAL"]
        high = [f for f in findings if f["severity"] == "HIGH"]
        
        if critical or high:
            console.print(Panel(
                "\n".join([
                    f"[bold]{f['vulnerability']}[/bold]\n  {f['description']}\n  Impact: {f['impact']}"
                    for f in (critical + high)[:5]
                ]),
                title="[bold red]⚠ CORS VULNERABILITIES FOUND[/bold red]",
                border_style="red"
            ))
        
        # Full table
        table = Table(title="CORS Scan Results", border_style="cyan")
        table.add_column("Severity", width=10)
        table.add_column("Issue", width=25)
        table.add_column("ACAO Value", width=30)
        table.add_column("Credentials")
        
        for f in findings:
            sev = f["severity"]
            if sev == "CRITICAL":
                sev_style = "[bold red]CRITICAL[/bold red]"
            elif sev == "HIGH":
                sev_style = "[red]HIGH[/red]"
            elif sev == "MEDIUM":
                sev_style = "[yellow]MEDIUM[/yellow]"
            else:
                sev_style = "[dim]LOW[/dim]"
            
            table.add_row(
                sev_style,
                f["vulnerability"],
                f.get("acao", "N/A")[:30],
                f.get("acac", "N/A")
            )
        
        console.print(table)
        
        # Save to loot
        save_loot("cors", url, {
            "target": url,
            "domain": target_domain,
            "findings": findings,
            "total": len(findings),
            "critical": len([f for f in findings if f["severity"] == "CRITICAL"]),
            "high": len([f for f in findings if f["severity"] == "HIGH"]),
        })
        
        log_success(f"Found {len(findings)} CORS issues!")
    else:
        log_info("No CORS misconfigurations found")
        console.print("[green]✓ CORS configuration appears secure[/green]")
    
    return findings
