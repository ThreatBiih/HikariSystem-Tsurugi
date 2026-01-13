# HikariSystem Tsurugi/core/waf.py
"""
WAF FINGERPRINTING - Identify and bypass Web Application Firewalls.
Detects specific WAF vendors and suggests appropriate bypass techniques.

Supported WAFs:
- Cloudflare, Akamai, Imperva/Incapsula
- AWS WAF, Azure WAF, Google Cloud Armor
- ModSecurity, NGINX, Apache
- Sucuri, F5 BIG-IP, Fortinet
"""
import re
from typing import Optional, Dict, List, Tuple
from dataclasses import dataclass
from core.ui import console, log_info, log_warning


@dataclass
class WAFSignature:
    """WAF detection signature."""
    name: str
    vendor: str
    headers: Dict[str, str]  # header_name -> regex pattern
    body_patterns: List[str]
    status_codes: List[int]
    cookies: List[str]
    bypass_techniques: List[str]


# WAF Signatures Database
WAF_SIGNATURES = [
    WAFSignature(
        name="Cloudflare",
        vendor="Cloudflare Inc.",
        headers={
            "cf-ray": r".*",
            "cf-cache-status": r".*",
            "server": r"cloudflare",
            "cf-mitigated": r".*",
        },
        body_patterns=[
            r"cloudflare",
            r"attention required",
            r"please wait.*while we",
            r"checking your browser",
            r"ray id:",
            r"cf-browser-verification",
        ],
        status_codes=[403, 503, 520, 521, 522, 523, 524],
        cookies=["__cf_bm", "__cfduid", "cf_clearance"],
        bypass_techniques=[
            "HPP (HTTP Parameter Pollution)",
            "Chunked Transfer Encoding",
            "Unicode normalization bypass",
            "Case variation",
            "Newline injection (%0a)",
            "Origin header spoofing",
        ]
    ),
    WAFSignature(
        name="Akamai",
        vendor="Akamai Technologies",
        headers={
            "x-akamai-transformed": r".*",
            "akamai-grn": r".*",
            "server": r"akamaighost",
            "x-akamai-session-info": r".*",
        },
        body_patterns=[
            r"akamai",
            r"access denied.*akamai",
            r"reference\s*#[a-f0-9\.]+",
        ],
        status_codes=[403],
        cookies=["ak_bmsc", "bm_sz", "bm_sv"],
        bypass_techniques=[
            "HPP (HTTP Parameter Pollution)",
            "Null byte injection",
            "Double URL encoding",
            "Form data vs URL params",
        ]
    ),
    WAFSignature(
        name="Imperva/Incapsula",
        vendor="Imperva Inc.",
        headers={
            "x-iinfo": r".*",
            "x-cdn": r"incapsula",
        },
        body_patterns=[
            r"incapsula",
            r"imperva",
            r"powered by incapsula",
            r"request unsuccessful",
            r"incident id",
        ],
        status_codes=[403],
        cookies=["incap_ses_", "visid_incap_"],
        bypass_techniques=[
            "HTTP method override (X-HTTP-Method-Override)",
            "Comment injection in SQL",
            "Chunked encoding",
            "Case randomization",
        ]
    ),
    WAFSignature(
        name="AWS WAF",
        vendor="Amazon Web Services",
        headers={
            "x-amzn-requestid": r".*",
            "x-amz-cf-id": r".*",
        },
        body_patterns=[
            r"aws",
            r"request blocked",
            r"waf",
        ],
        status_codes=[403],
        cookies=[],
        bypass_techniques=[
            "Case variation (sElEcT, ScRiPt)",
            "Unicode homoglyphs",
            "HPP",
            "Comment injection",
            "Inline comments in SQL (/*!50000SELECT*/)",
        ]
    ),
    WAFSignature(
        name="ModSecurity",
        vendor="Trustwave/OWASP",
        headers={
            "server": r"mod_security|modsecurity",
        },
        body_patterns=[
            r"mod_security",
            r"modsecurity",
            r"not acceptable",
            r"rule id",
            r"owasp",
        ],
        status_codes=[403, 406],
        cookies=[],
        bypass_techniques=[
            "Comment injection (/*!...*/)",
            "Null byte (%00)",
            "HPP",
            "Tab instead of space",
            "Case variation",
            "Encoding chains (double/triple encoding)",
        ]
    ),
    WAFSignature(
        name="Sucuri",
        vendor="GoDaddy/Sucuri",
        headers={
            "x-sucuri-id": r".*",
            "server": r"sucuri",
            "x-sucuri-cache": r".*",
        },
        body_patterns=[
            r"sucuri",
            r"access denied.*sucuri",
            r"sucuri website firewall",
        ],
        status_codes=[403],
        cookies=["sucuri_cloudproxy"],
        bypass_techniques=[
            "Origin IP bypass",
            "X-Forwarded-For spoofing",
            "HPP",
        ]
    ),
    WAFSignature(
        name="F5 BIG-IP ASM",
        vendor="F5 Networks",
        headers={
            "server": r"big-ip|bigip|f5",
            "x-wa-info": r".*",
        },
        body_patterns=[
            r"f5 network",
            r"support id",
            r"the requested url was rejected",
        ],
        status_codes=[403],
        cookies=["f5avraaaaaaa", "TS"],
        bypass_techniques=[
            "Chunked encoding",
            "JSON injection",
            "Unicode bypass",
        ]
    ),
    WAFSignature(
        name="Fortinet FortiWeb",
        vendor="Fortinet",
        headers={
            "server": r"fortiweb",
        },
        body_patterns=[
            r"fortigate",
            r"fortiweb",
            r"fortinet",
        ],
        status_codes=[403],
        cookies=["FORTIWAFSID"],
        bypass_techniques=[
            "Case randomization",
            "Null bytes",
            "HPP",
        ]
    ),
    WAFSignature(
        name="Azure WAF",
        vendor="Microsoft Azure",
        headers={
            "x-azure-ref": r".*",
            "x-ms-routing-requestid": r".*",
        },
        body_patterns=[
            r"azure",
            r"microsoft",
        ],
        status_codes=[403],
        cookies=[],
        bypass_techniques=[
            "Unicode bypass",
            "Encoding chains",
            "HTTP Verb tampering",
        ]
    ),
    WAFSignature(
        name="Google Cloud Armor",
        vendor="Google Cloud",
        headers={},
        body_patterns=[
            r"google cloud",
            r"blocked by security policy",
        ],
        status_codes=[403],
        cookies=[],
        bypass_techniques=[
            "Case variation",
            "Encoding bypass",
            "Fragmentation",
        ]
    ),
]


@dataclass
class WAFResult:
    """WAF detection result."""
    detected: bool
    waf_name: str = None
    vendor: str = None
    confidence: str = "none"  # none, low, medium, high
    bypass_techniques: List[str] = None
    evidence: List[str] = None


def fingerprint_waf(response) -> WAFResult:
    """
    Fingerprint WAF from HTTP response.
    
    Args:
        response: HTTP response object
        
    Returns:
        WAFResult with detection info
    """
    if response is None:
        return WAFResult(detected=False)
    
    evidence = []
    
    # Get response data
    headers = {k.lower(): v for k, v in response.headers.items()} if hasattr(response, 'headers') else {}
    body = response.text.lower() if hasattr(response, 'text') else ''
    status = response.status_code if hasattr(response, 'status_code') else 0
    cookies = list(response.cookies.keys()) if hasattr(response, 'cookies') else []
    
    for sig in WAF_SIGNATURES:
        score = 0
        
        # Check headers
        for header, pattern in sig.headers.items():
            if header in headers:
                if re.search(pattern, headers[header], re.I):
                    score += 2
                    evidence.append(f"Header match: {header}")
        
        # Check body patterns
        for pattern in sig.body_patterns:
            if re.search(pattern, body, re.I):
                score += 1
                evidence.append(f"Body match: {pattern[:30]}")
        
        # Check status codes
        if status in sig.status_codes:
            score += 1
            evidence.append(f"Status code: {status}")
        
        # Check cookies
        for cookie_prefix in sig.cookies:
            for cookie in cookies:
                if cookie.startswith(cookie_prefix) or cookie_prefix in cookie:
                    score += 2
                    evidence.append(f"Cookie match: {cookie}")
        
        # Determine confidence
        if score >= 4:
            confidence = "high"
        elif score >= 2:
            confidence = "medium"
        elif score >= 1:
            confidence = "low"
        else:
            continue
        
        return WAFResult(
            detected=True,
            waf_name=sig.name,
            vendor=sig.vendor,
            confidence=confidence,
            bypass_techniques=sig.bypass_techniques,
            evidence=evidence[:5]
        )
    
    # Generic WAF detection
    generic_patterns = [
        r"access denied", r"forbidden", r"blocked",
        r"security", r"waf", r"firewall",
        r"not allowed", r"suspicious", r"malicious",
    ]
    
    for pattern in generic_patterns:
        if re.search(pattern, body, re.I) and status in [403, 406, 429]:
            evidence.append(f"Generic: {pattern} in body")
            return WAFResult(
                detected=True,
                waf_name="Unknown WAF",
                vendor="Unknown",
                confidence="low",
                bypass_techniques=[
                    "Double URL encoding",
                    "Case variation",
                    "HPP",
                    "Null bytes",
                    "Unicode bypass",
                ],
                evidence=evidence[:5]
            )
    
    return WAFResult(detected=False)


def print_waf_result(result: WAFResult):
    """Print WAF detection result to console."""
    from rich.panel import Panel
    from rich.table import Table
    
    if not result.detected:
        console.print("[green]✓ No WAF detected[/green]")
        return
    
    # Build bypass table
    table = Table(show_header=False, border_style="dim")
    table.add_column("Technique")
    
    for technique in (result.bypass_techniques or [])[:6]:
        table.add_row(f"• {technique}")
    
    console.print(Panel(
        f"[bold]WAF:[/bold] {result.waf_name}\n"
        f"[bold]Vendor:[/bold] {result.vendor}\n"
        f"[bold]Confidence:[/bold] {result.confidence.upper()}\n\n"
        f"[bold yellow]Suggested Bypass Techniques:[/bold yellow]",
        title=f"[bold red]🛡️ WAF DETECTED[/bold red]",
        border_style="red"
    ))
    console.print(table)
    
    if result.evidence:
        console.print(f"[dim]Evidence: {', '.join(result.evidence[:3])}[/dim]")


def detect_and_suggest(url: str, requester) -> WAFResult:
    """
    Detect WAF and suggest bypass techniques.
    
    Args:
        url: Target URL
        requester: TsurugiSession instance
        
    Returns:
        WAFResult
    """
    console.print(f"\n[bold cyan][*] WAF FINGERPRINTING[/bold cyan] → {url}")
    
    # Send probe request
    response = requester.get(url, timeout=10)
    
    result = fingerprint_waf(response)
    print_waf_result(result)
    
    return result


def get_bypass_payloads(waf_name: str, base_payload: str) -> List[str]:
    """
    Generate bypass variations for a specific WAF.
    
    Args:
        waf_name: Detected WAF name
        base_payload: Original payload to mutate
        
    Returns:
        List of bypass payload variations
    """
    variations = [base_payload]
    
    # Find WAF signature
    sig = next((s for s in WAF_SIGNATURES if s.name.lower() == waf_name.lower()), None)
    
    if not sig:
        # Generic bypasses
        variations.extend([
            base_payload.replace(" ", "/**/"),  # Comment bypass
            base_payload.replace("'", "%27"),   # URL encode
            base_payload.replace("<", "%3C"),   # URL encode
            base_payload.upper(),               # Case variation
        ])
        return variations
    
    # WAF-specific mutations
    if "cloudflare" in waf_name.lower():
        variations.extend([
            base_payload + "%0a",  # Newline injection
            base_payload.replace("'", "\u2019"),  # Unicode
            base_payload.replace(" ", "\t"),  # Tab instead of space
        ])
    
    elif "modsecurity" in waf_name.lower():
        variations.extend([
            base_payload.replace("SELECT", "/*!50000SELECT*/"),
            base_payload.replace("UNION", "/*!UNION*/"),
            base_payload + "%00",  # Null byte
        ])
    
    elif "aws" in waf_name.lower():
        # Case randomization
        import random
        randomized = ''.join(c.upper() if random.random() > 0.5 else c.lower() for c in base_payload)
        variations.append(randomized)
        # Double encode
        import urllib.parse
        variations.append(urllib.parse.quote(urllib.parse.quote(base_payload)))
    
    elif "akamai" in waf_name.lower():
        variations.extend([
            base_payload + "&" + base_payload,  # HPP
            base_payload.replace("<", "\\x3c"),  # Hex encoding
        ])
    
    return variations
