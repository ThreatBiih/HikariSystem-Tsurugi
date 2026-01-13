# HikariSystem Tsurugi/modules/secrets.py
"""
SECRETS MODULE - Detects and VERIFIES API keys, tokens, and credentials
Patterns adapted from HikariSystem JSA with active verification
"""
import re
import json
import base64
import requests
from typing import Dict, List, Tuple, Optional
from datetime import datetime
from core.ui import console, log_info, log_success, log_warning, log_error
from core.logger import save_loot
from rich.panel import Panel
from rich.table import Table

# Disable SSL warnings for verification requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Secret patterns: (compiled_regex, secret_type, severity, verifier_key)
SECRET_PATTERNS = [
    # AWS
    (re.compile(r'(AKIA[0-9A-Z]{16})'), "AWS Access Key ID", "critical", "aws"),
    
    # Google
    (re.compile(r'(AIza[0-9A-Za-z\-_]{35})'), "Google API Key", "high", "google"),
    (re.compile(r'(\d+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com)'), "Google OAuth Client ID", "medium", None),
    
    # Stripe
    (re.compile(r'(sk_live_[0-9a-zA-Z]{24,})'), "Stripe Live Secret Key", "critical", "stripe"),
    (re.compile(r'(sk_test_[0-9a-zA-Z]{24,})'), "Stripe Test Secret Key", "low", "stripe"),
    (re.compile(r'(pk_live_[0-9a-zA-Z]{24,})'), "Stripe Live Publishable Key", "medium", None),
    (re.compile(r'(rk_live_[0-9a-zA-Z]{24,})'), "Stripe Restricted Key", "high", "stripe"),
    
    # GitHub
    (re.compile(r'(ghp_[0-9a-zA-Z]{36})'), "GitHub Personal Access Token", "critical", "github"),
    (re.compile(r'(gho_[0-9a-zA-Z]{36})'), "GitHub OAuth Token", "critical", "github"),
    (re.compile(r'(ghu_[0-9a-zA-Z]{36})'), "GitHub User Token", "critical", "github"),
    (re.compile(r'(ghs_[0-9a-zA-Z]{36})'), "GitHub Server Token", "critical", "github"),
    (re.compile(r'(ghr_[0-9a-zA-Z]{36})'), "GitHub Refresh Token", "critical", None),
    
    # Slack
    (re.compile(r'(xox[baprs]-[0-9a-zA-Z\-]{10,48})'), "Slack Token", "critical", "slack"),
    (re.compile(r'(https://hooks\.slack\.com/services/[A-Za-z0-9/]+)'), "Slack Webhook", "high", "slack_webhook"),
    
    # Discord
    (re.compile(r'(https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+)'), "Discord Webhook", "high", "discord_webhook"),
    (re.compile(r'([MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27})'), "Discord Bot Token", "critical", "discord"),
    
    # JWT
    (re.compile(r'(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+)'), "JWT Token", "medium", "jwt"),
    
    # Private Keys
    (re.compile(r'(-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----)'), "Private Key", "critical", None),
    (re.compile(r'(-----BEGIN PGP PRIVATE KEY BLOCK-----)'), "PGP Private Key", "critical", None),
    
    # Database URIs
    (re.compile(r'(mongodb(?:\+srv)?://[^\s"\'<>]+)'), "MongoDB Connection String", "critical", None),
    (re.compile(r'(postgres(?:ql)?://[^\s"\'<>]+)'), "PostgreSQL Connection String", "critical", None),
    (re.compile(r'(mysql://[^\s"\'<>]+)'), "MySQL Connection String", "critical", None),
    (re.compile(r'(redis://[^\s"\'<>]+)'), "Redis Connection String", "high", None),
    
    # Twilio
    (re.compile(r'(SK[0-9a-fA-F]{32})'), "Twilio API Key", "high", None),
    (re.compile(r'(AC[0-9a-fA-F]{32})'), "Twilio Account SID", "medium", None),
    
    # SendGrid
    (re.compile(r'(SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43})'), "SendGrid API Key", "critical", "sendgrid"),
    
    # Mailgun
    (re.compile(r'(key-[0-9a-zA-Z]{32})'), "Mailgun API Key", "high", None),
    
    # Heroku
    (re.compile(r'(heroku[a-z0-9_-]*[=:][a-z0-9_-]{30,})', re.I), "Heroku API Key", "high", None),
    
    # Firebase
    (re.compile(r'(AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140})'), "Firebase Cloud Messaging Key", "high", None),
    
    # Generic API Keys (heuristic)
    (re.compile(r'["\']?api[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', re.I), "Generic API Key", "medium", None),
    (re.compile(r'["\']?secret[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', re.I), "Generic Secret Key", "high", None),
    (re.compile(r'["\']?access[_-]?token["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', re.I), "Generic Access Token", "high", None),
    (re.compile(r'["\']?auth[_-]?token["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', re.I), "Generic Auth Token", "high", None),
    
    # Password patterns (in config/code)
    (re.compile(r'["\']?password["\']?\s*[:=]\s*["\']([^"\']{8,})["\']', re.I), "Hardcoded Password", "high", None),
]

# False positive filters
FALSE_POSITIVE_PATTERNS = [
    re.compile(r'^example', re.I),
    re.compile(r'^test', re.I),
    re.compile(r'^placeholder', re.I),
    re.compile(r'^your[_-]', re.I),
    re.compile(r'xxxx', re.I),
    re.compile(r'^0+$'),
    re.compile(r'^1234'),
    re.compile(r'^abcd', re.I),
    re.compile(r'^\*+$'),
    re.compile(r'^TODO', re.I),
    re.compile(r'^FIXME', re.I),
]


# ═══════════════════════════════════════════════════════════════════════════════
#  ACTIVE VERIFIERS
# ═══════════════════════════════════════════════════════════════════════════════

def verify_github(token: str) -> Tuple[bool, str]:
    """Verify GitHub token by calling /user endpoint."""
    try:
        resp = requests.get(
            "https://api.github.com/user",
            headers={"Authorization": f"token {token}", "User-Agent": "Tsurugi-Scanner"},
            timeout=10
        )
        if resp.status_code == 200:
            data = resp.json()
            return True, f"User: {data.get('login', '?')}, Scopes: {resp.headers.get('X-OAuth-Scopes', 'N/A')}"
        elif resp.status_code == 401:
            return False, "Invalid/Expired"
        else:
            return False, f"HTTP {resp.status_code}"
    except Exception as e:
        return None, f"Error: {str(e)[:30]}"


def verify_stripe(key: str) -> Tuple[bool, str]:
    """Verify Stripe key by calling /v1/balance."""
    try:
        resp = requests.get(
            "https://api.stripe.com/v1/balance",
            auth=(key, ""),
            timeout=10
        )
        if resp.status_code == 200:
            data = resp.json()
            mode = "LIVE" if "livemode" in str(data) and data.get("livemode") else "TEST"
            return True, f"Mode: {mode}"
        elif resp.status_code == 401:
            return False, "Invalid Key"
        else:
            return False, f"HTTP {resp.status_code}"
    except Exception as e:
        return None, f"Error: {str(e)[:30]}"


def verify_slack(token: str) -> Tuple[bool, str]:
    """Verify Slack token via auth.test."""
    try:
        resp = requests.post(
            "https://slack.com/api/auth.test",
            headers={"Authorization": f"Bearer {token}"},
            timeout=10
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("ok"):
                return True, f"Team: {data.get('team', '?')}, User: {data.get('user', '?')}"
            else:
                return False, data.get("error", "Invalid")
        else:
            return False, f"HTTP {resp.status_code}"
    except Exception as e:
        return None, f"Error: {str(e)[:30]}"


def verify_slack_webhook(url: str) -> Tuple[bool, str]:
    """Verify Slack webhook by sending empty payload (won't post)."""
    try:
        # Send invalid payload to test if webhook exists without posting
        resp = requests.post(url, json={}, timeout=10)
        if resp.status_code == 400 and "no_text" in resp.text:
            return True, "Webhook Active"
        elif resp.status_code == 404:
            return False, "Webhook Not Found"
        else:
            return None, f"HTTP {resp.status_code}"
    except Exception as e:
        return None, f"Error: {str(e)[:30]}"


def verify_discord_webhook(url: str) -> Tuple[bool, str]:
    """Verify Discord webhook by GET request."""
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            return True, f"Channel: {data.get('name', '?')}"
        elif resp.status_code == 404:
            return False, "Webhook Not Found"
        else:
            return False, f"HTTP {resp.status_code}"
    except Exception as e:
        return None, f"Error: {str(e)[:30]}"


def verify_discord(token: str) -> Tuple[bool, str]:
    """Verify Discord bot token."""
    try:
        resp = requests.get(
            "https://discord.com/api/v10/users/@me",
            headers={"Authorization": f"Bot {token}"},
            timeout=10
        )
        if resp.status_code == 200:
            data = resp.json()
            return True, f"Bot: {data.get('username', '?')}#{data.get('discriminator', '0')}"
        elif resp.status_code == 401:
            return False, "Invalid Token"
        else:
            return False, f"HTTP {resp.status_code}"
    except Exception as e:
        return None, f"Error: {str(e)[:30]}"


def verify_sendgrid(key: str) -> Tuple[bool, str]:
    """Verify SendGrid API key."""
    try:
        resp = requests.get(
            "https://api.sendgrid.com/v3/user/profile",
            headers={"Authorization": f"Bearer {key}"},
            timeout=10
        )
        if resp.status_code == 200:
            return True, "Valid Key"
        elif resp.status_code == 401:
            return False, "Invalid Key"
        else:
            return False, f"HTTP {resp.status_code}"
    except Exception as e:
        return None, f"Error: {str(e)[:30]}"


def verify_google(key: str) -> Tuple[bool, str]:
    """Verify Google API key (basic check)."""
    try:
        # Try a simple geocoding request (free tier)
        resp = requests.get(
            f"https://maps.googleapis.com/maps/api/geocode/json?address=test&key={key}",
            timeout=10
        )
        data = resp.json()
        if data.get("status") == "OK" or data.get("status") == "ZERO_RESULTS":
            return True, "Key Active"
        elif data.get("status") == "REQUEST_DENIED":
            error = data.get("error_message", "")
            if "not authorized" in error.lower():
                return True, "Valid (API not enabled)"
            return False, "Invalid Key"
        else:
            return None, data.get("status", "Unknown")
    except Exception as e:
        return None, f"Error: {str(e)[:30]}"


def verify_jwt(token: str) -> Tuple[bool, str]:
    """Decode and analyze JWT token."""
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return False, "Invalid Format"
        
        # Decode payload (middle part)
        payload = parts[1]
        # Add padding if needed
        payload += "=" * (4 - len(payload) % 4)
        decoded = base64.urlsafe_b64decode(payload)
        data = json.loads(decoded)
        
        # Check expiration
        exp = data.get("exp")
        if exp:
            exp_time = datetime.fromtimestamp(exp)
            if exp_time < datetime.now():
                return False, f"Expired: {exp_time.strftime('%Y-%m-%d')}"
            else:
                return True, f"Valid until: {exp_time.strftime('%Y-%m-%d')}"
        
        # No expiration
        sub = data.get("sub", data.get("user_id", data.get("email", "?")))
        return True, f"No exp, sub: {str(sub)[:20]}"
    except Exception as e:
        return None, f"Decode error"


# Verifier mapping
VERIFIERS = {
    "github": verify_github,
    "stripe": verify_stripe,
    "slack": verify_slack,
    "slack_webhook": verify_slack_webhook,
    "discord_webhook": verify_discord_webhook,
    "discord": verify_discord,
    "sendgrid": verify_sendgrid,
    "google": verify_google,
    "jwt": verify_jwt,
}


def verify_secret(finding: Dict) -> Dict:
    """
    Verify a secret if a verifier is available.
    Updates the finding dict with verification results.
    """
    verifier_key = finding.get("verifier")
    if not verifier_key or verifier_key not in VERIFIERS:
        finding["verified"] = None
        finding["verify_msg"] = "No verifier"
        return finding
    
    verifier = VERIFIERS[verifier_key]
    is_valid, message = verifier(finding["value"])
    
    finding["verified"] = is_valid
    finding["verify_msg"] = message
    
    return finding


# ═══════════════════════════════════════════════════════════════════════════════
#  CORE FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

def is_false_positive(value: str) -> bool:
    """Check if value is likely a false positive."""
    if not value or len(value) < 8:
        return True
    
    for pattern in FALSE_POSITIVE_PATTERNS:
        if pattern.search(value):
            return True
    
    # Check entropy (low entropy = likely false positive)
    unique_chars = len(set(value))
    if unique_chars < 4:
        return True
    
    return False


def mask_secret(value: str, reveal: int = 8) -> str:
    """Mask a secret for safe display."""
    if len(value) <= reveal * 2:
        return value[:reveal] + "..."
    return value[:reveal] + "..." + value[-4:]


def scan_for_secrets(content: str, source_url: str = None) -> List[Dict]:
    """
    Scan content for secrets and credentials.
    """
    findings = []
    seen = set()
    
    for pattern, secret_type, severity, verifier_key in SECRET_PATTERNS:
        for match in pattern.finditer(content):
            value = match.group(1) if match.lastindex else match.group(0)
            value = value.strip()
            
            if value in seen:
                continue
            
            if is_false_positive(value):
                continue
            
            seen.add(value)
            
            finding = {
                "type": secret_type,
                "value": value,
                "masked": mask_secret(value),
                "severity": severity,
                "source": source_url or "unknown",
                "verifier": verifier_key,
                "verified": None,
                "verify_msg": None
            }
            findings.append(finding)
    
    return findings


def display_secrets(findings: List[Dict], show_verification: bool = False):
    """Display found secrets in console."""
    if not findings:
        return
    
    if show_verification:
        # Rich table with verification status
        table = Table(title="🔑 Secrets Found", border_style="cyan")
        table.add_column("Type", style="bold")
        table.add_column("Value", style="dim")
        table.add_column("Severity")
        table.add_column("Status")
        table.add_column("Details")
        
        for f in findings:
            # Severity color
            sev = f["severity"]
            if sev == "critical":
                sev_style = "[bold red]CRITICAL[/bold red]"
            elif sev == "high":
                sev_style = "[yellow]HIGH[/yellow]"
            elif sev == "medium":
                sev_style = "[blue]MEDIUM[/blue]"
            else:
                sev_style = "[dim]LOW[/dim]"
            
            # Verification status
            verified = f.get("verified")
            if verified is True:
                status = "[bold green]✓ VALID[/bold green]"
            elif verified is False:
                status = "[red]✗ INVALID[/red]"
            else:
                status = "[dim]? N/A[/dim]"
            
            table.add_row(
                f["type"],
                f["masked"],
                sev_style,
                status,
                f.get("verify_msg", "-") or "-"
            )
        
        console.print(table)
    
    else:
        # Original grouped display
        critical = [f for f in findings if f["severity"] == "critical"]
        high = [f for f in findings if f["severity"] == "high"]
        medium = [f for f in findings if f["severity"] == "medium"]
        low = [f for f in findings if f["severity"] == "low"]
        
        if critical:
            console.print(Panel(
                "\n".join([f"[bold]{f['type']}[/bold]: {f['masked']}" for f in critical]),
                title="[bold red]⚠ CRITICAL SECRETS[/bold red]",
                border_style="red"
            ))
        
        if high:
            console.print(Panel(
                "\n".join([f"[bold]{f['type']}[/bold]: {f['masked']}" for f in high]),
                title="[bold yellow]HIGH SEVERITY[/bold yellow]",
                border_style="yellow"
            ))
        
        if medium:
            for f in medium:
                log_warning(f"[MEDIUM] {f['type']}: {f['masked']}")
        
        if low:
            for f in low:
                log_info(f"[LOW] {f['type']}: {f['masked']}")


def run_secrets_scan(url: str, content: str = None, cookie: str = None, proxy: str = None, 
                     headless: bool = False, verify: bool = False) -> List[Dict]:
    """
    Run secrets scan on a URL or provided content.
    
    Args:
        url: Target URL (will fetch if content not provided)
        content: Optional pre-fetched content
        cookie: Session cookie
        proxy: Proxy URL
        headless: Use headless browser
        verify: Actively verify found secrets
        
    Returns:
        List of found secrets
    """
    console.print(f"\n[bold magenta][*] SECRETS SCAN[/bold magenta] → [yellow]{url}[/yellow]")
    
    if verify:
        console.print("[bold cyan][*] Active verification ENABLED[/bold cyan]")
    
    if not content:
        from core.requester import TsurugiSession
        session = TsurugiSession(cookie_string=cookie, proxy=proxy)
        
        resp = session.get(url, timeout=15)
        if not resp:
            log_error("Failed to fetch URL")
            return []
        
        content = resp.text
    
    log_info(f"Scanning {len(content)} bytes...")
    
    findings = scan_for_secrets(content, url)
    
    if findings:
        log_success(f"Found {len(findings)} potential secrets!")
        
        # Verify if requested
        if verify:
            console.print("[*] Verifying secrets...")
            for finding in findings:
                if finding.get("verifier"):
                    verify_secret(finding)
        
        display_secrets(findings, show_verification=verify)
        
        # Save to loot (only verified or unverified critical/high)
        for finding in findings:
            if finding["severity"] in ("critical", "high"):
                # If verification was done, only save valid ones
                if verify and finding.get("verified") is False:
                    continue
                    
                save_loot("secrets", url, {
                    "type": finding["type"],
                    "value": finding["value"],
                    "severity": finding["severity"],
                    "verified": finding.get("verified"),
                    "verify_msg": finding.get("verify_msg")
                })
    else:
        log_info("No secrets found")
    
    return findings

