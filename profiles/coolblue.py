# HikariSystem Tsurugi/profiles/coolblue.py
"""
Coolblue Bug Bounty Program Profile
Intigriti Bug Bounty

Rate Limits:
- Netherlands, Belgium, Germany: 2 req/sec
- Other countries: 0.3 req/sec (1 request every 3 seconds)

In Scope (Tier 2):
- www.coolblue.nl
- www.coolblue.be
- www.coolblue.de
- mobile-api.coolblue-production.eu

Focus Areas:
- Unauthorized access to infrastructure/databases
- Exploits in order process (free/discounted products)
- Customer data exposure (emails, addresses, order history)
- Encrypted password exposure
"""

import os

# ============================================================================
# PROGRAM CONFIGURATION
# ============================================================================

PROGRAM_NAME = "Coolblue"
PLATFORM = "Intigriti"
PROGRAM_URL = "https://app.intigriti.com/programs/coolblue"

# Rate limit: 0.3 req/sec = 1 request every 3.33 seconds = 3333ms
# Using 3500ms to be safe
RATE_LIMIT_MS = 3500

# ============================================================================
# IN-SCOPE ASSETS
# ============================================================================

TARGETS = {
    "tier2": [
        "https://www.coolblue.nl",
        "https://www.coolblue.be",
        "https://www.coolblue.de",
        "https://mobile-api.coolblue-production.eu",
    ],
    "tier3": [
        "https://werkenbijcoolblue.nl",
        "https://werkenbijcoolblue.be",
        "https://werkenbijcoolblue.com",
        "https://careersatcoolblue.com",
        "https://arbeitenbeicoolblue.de",
        "https://travaillerchezcoolblue.be",
    ],
    "mobile": [
        "eu.coolblue.shop (Android)",
        "1174047097 (iOS)",
    ]
}

# ============================================================================
# HEADERS
# ============================================================================

# Required: Use @intigriti.me email for tracing
INTIGRITI_USERNAME = os.environ.get("INTIGRITI_USERNAME", "your_username")

CUSTOM_HEADERS = {
    "X-Intigriti-Researcher": f"{INTIGRITI_USERNAME}@intigriti.me",
    "X-Bug-Bounty": "Coolblue-Intigriti",
}

# ============================================================================
# OUT OF SCOPE (DO NOT TEST)
# ============================================================================

OUT_OF_SCOPE = [
    "Email Address completion on login form",
    "No customer website session expire",
    "No session reset after password change",
    "No password length requirement",
    "No email verification for accounts",
    "No captcha on customer login",
    "Leaked credentials",
    "UUID endpoints",
    "API key disclosure without impact",
    "WordPress username disclosure",
    "Self-XSS",
    "CORS on non-sensitive endpoints",
    "Missing cookie flags",
    "Missing security headers",
    "Low impact CSRF",
    "Clickjacking without impact",
    "CSV Injection",
    "Rate limit bypass",
    "Content injection without HTML modification",
    "Username/email enumeration",
    "Email bombing",
    "Subdomain takeover without takeover",
    "Blind SSRF without impact",
    "Host header injection without impact",
]

# ============================================================================
# FOCUS AREAS (HIGH VALUE)
# ============================================================================

FOCUS_AREAS = [
    "Order process exploits (free/discounted products)",
    "Customer data exposure (PII, order history)",
    "Payment data exposure",
    "Unauthorized backend/database access",
    "Authentication bypass",
    "IDOR on customer/order endpoints",
]

# ============================================================================
# ENVIRONMENT VARIABLES TO SET
# ============================================================================

def get_env_config():
    """Get environment configuration for this program."""
    return {
        "TSURUGI_RATE_LIMIT": str(RATE_LIMIT_MS),
        "TSURUGI_USER_AGENT": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "TSURUGI_CUSTOM_HEADER": f"X-Intigriti-Researcher:{INTIGRITI_USERNAME}@intigriti.me",
    }


def print_scope():
    """Print the program scope."""
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    
    console = Console()
    
    console.print(Panel.fit(
        f"[cyan]{PROGRAM_NAME}[/cyan] Bug Bounty Profile\n"
        f"Platform: [white]{PLATFORM}[/white]\n"
        f"Rate Limit: [yellow]{RATE_LIMIT_MS}ms ({1000/RATE_LIMIT_MS:.2f} req/sec)[/yellow]",
        title="TSURUGI PROFILE",
        border_style="cyan"
    ))
    
    # Targets table
    table = Table(title="In-Scope Targets", show_header=True)
    table.add_column("Tier", style="cyan", width=8)
    table.add_column("Target", width=50)
    
    for tier, targets in TARGETS.items():
        for target in targets:
            table.add_row(tier, target)
    
    console.print(table)
    
    # Focus areas
    console.print("\n[bold yellow]Focus Areas:[/bold yellow]")
    for area in FOCUS_AREAS:
        console.print(f"  [green]•[/green] {area}")
    
    # Out of scope summary
    console.print(f"\n[dim]Out of scope: {len(OUT_OF_SCOPE)} items (see profile for details)[/dim]")


if __name__ == "__main__":
    print_scope()
