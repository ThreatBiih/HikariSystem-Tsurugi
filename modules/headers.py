# HikariSystem Tsurugi/modules/headers.py
"""
SECURITY HEADERS SCANNER
Checks for important security headers and misconfigurations
"""
from typing import Dict, List
from urllib.parse import urlparse
from core.ui import console, log_info, log_success, log_warning, log_error
from core.logger import save_loot
from core.requester import TsurugiSession
from rich.panel import Panel
from rich.table import Table

# Security headers to check
SECURITY_HEADERS = {
    # Critical headers
    "Strict-Transport-Security": {
        "severity": "high",
        "description": "HSTS - Forces HTTPS connections",
        "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"
    },
    "Content-Security-Policy": {
        "severity": "high",
        "description": "CSP - Prevents XSS and injection attacks",
        "recommendation": "Add a restrictive CSP policy"
    },
    "X-Frame-Options": {
        "severity": "medium",
        "description": "Anti-clickjacking protection",
        "recommendation": "Add: X-Frame-Options: DENY or SAMEORIGIN"
    },
    "X-Content-Type-Options": {
        "severity": "medium",
        "description": "Prevents MIME type sniffing",
        "recommendation": "Add: X-Content-Type-Options: nosniff"
    },
    "X-XSS-Protection": {
        "severity": "low",
        "description": "Legacy XSS filter (mostly deprecated)",
        "recommendation": "Add: X-XSS-Protection: 1; mode=block"
    },
    "Referrer-Policy": {
        "severity": "low",
        "description": "Controls referrer information",
        "recommendation": "Add: Referrer-Policy: strict-origin-when-cross-origin"
    },
    "Permissions-Policy": {
        "severity": "low",
        "description": "Controls browser features (camera, mic, etc)",
        "recommendation": "Add restrictive Permissions-Policy"
    },
}

# Dangerous headers that shouldn't be exposed
DANGEROUS_HEADERS = {
    "Server": "Exposes server software version",
    "X-Powered-By": "Exposes backend technology",
    "X-AspNet-Version": "Exposes ASP.NET version",
    "X-AspNetMvc-Version": "Exposes MVC version",
}


def check_security_headers(url: str, proxy: str = None) -> Dict:
    """
    Check security headers for a given URL.
    
    Returns:
        dict with present headers, missing headers, and dangerous headers
    """
    # Use TsurugiSession for TLS stealth
    session = TsurugiSession(proxy=proxy)
    
    try:
        resp = session.get(url, timeout=10, allow_redirects=True)
        
        if resp is None:
            return {"error": "Request failed"}
        
        response_headers = {k.lower(): v for k, v in resp.headers.items()}
        
        present = {}
        missing = {}
        dangerous = {}
        
        # Check for security headers
        for header, info in SECURITY_HEADERS.items():
            header_lower = header.lower()
            if header_lower in response_headers:
                present[header] = {
                    "value": response_headers[header_lower],
                    "severity": info["severity"],
                    "description": info["description"]
                }
            else:
                missing[header] = info
        
        # Check for dangerous headers
        for header, desc in DANGEROUS_HEADERS.items():
            header_lower = header.lower()
            if header_lower in response_headers:
                dangerous[header] = {
                    "value": response_headers[header_lower],
                    "description": desc
                }
        
        return {
            "url": url,
            "status_code": resp.status_code,
            "present": present,
            "missing": missing,
            "dangerous": dangerous,
            "all_headers": dict(resp.headers)
        }
        
    except Exception as e:
        return {"error": str(e)}


def calculate_score(result: Dict) -> int:
    """Calculate security score based on headers (0-100)."""
    if "error" in result:
        return 0
    
    score = 100
    
    # Deduct for missing headers
    for header, info in result["missing"].items():
        if info["severity"] == "high":
            score -= 20
        elif info["severity"] == "medium":
            score -= 10
        else:
            score -= 5
    
    # Deduct for dangerous headers
    score -= len(result["dangerous"]) * 5
    
    return max(0, score)


def run_headers_scan(url: str, proxy: str = None) -> Dict:
    """
    Run comprehensive security headers scan.
    """
    console.print(f"\n[bold magenta][*] SECURITY HEADERS SCANNER[/bold magenta] -> [yellow]{url}[/yellow]")
    
    result = check_security_headers(url, proxy)
    
    if "error" in result:
        log_error(f"Scan failed: {result['error']}")
        return result
    
    score = calculate_score(result)
    
    # Display score
    if score >= 80:
        score_color = "green"
        score_text = "GOOD"
    elif score >= 50:
        score_color = "yellow"
        score_text = "FAIR"
    else:
        score_color = "red"
        score_text = "POOR"
    
    console.print(Panel(
        f"[bold {score_color}]{score}/100[/bold {score_color}] - {score_text}",
        title="Security Score",
        border_style=score_color
    ))
    
    # Present headers (good)
    if result["present"]:
        console.print("\n[bold green]✓ Present Security Headers:[/bold green]")
        for header, info in result["present"].items():
            console.print(f"  [green]✓[/green] {header}: [dim]{info['value'][:50]}...[/dim]" if len(info['value']) > 50 else f"  [green]✓[/green] {header}: [dim]{info['value']}[/dim]")
    
    # Missing headers (bad)
    if result["missing"]:
        console.print("\n[bold red]✗ Missing Security Headers:[/bold red]")
        for header, info in result["missing"].items():
            sev = info["severity"]
            if sev == "high":
                console.print(f"  [red]✗[/red] {header} [red](HIGH)[/red] - {info['description']}")
            elif sev == "medium":
                console.print(f"  [yellow]✗[/yellow] {header} [yellow](MEDIUM)[/yellow] - {info['description']}")
            else:
                console.print(f"  [dim]✗ {header} (LOW) - {info['description']}[/dim]")
    
    # Dangerous headers (info leak)
    if result["dangerous"]:
        console.print("\n[bold yellow]⚠ Information Disclosure:[/bold yellow]")
        for header, info in result["dangerous"].items():
            console.print(f"  [yellow]![/yellow] {header}: {info['value']} - {info['description']}")
    
    # Recommendations table
    if result["missing"]:
        high_missing = [h for h, i in result["missing"].items() if i["severity"] == "high"]
        if high_missing:
            console.print("\n[bold]Recommendations:[/bold]")
            for header in high_missing:
                console.print(f"  → {result['missing'][header]['recommendation']}")
    
    # Save to loot
    save_loot("headers", url, {
        "score": score,
        "present": list(result["present"].keys()),
        "missing": list(result["missing"].keys()),
        "dangerous": list(result["dangerous"].keys()),
        "details": result
    })
    
    log_success(f"Scan complete. Score: {score}/100")
    
    return result
