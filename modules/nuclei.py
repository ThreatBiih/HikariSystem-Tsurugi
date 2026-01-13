# HikariSystem Tsurugi/modules/nuclei.py
"""
NUCLEI INTEGRATION MODULE
Wrapper for ProjectDiscovery's Nuclei scanner
Provides access to 6000+ vulnerability templates
"""
import json
import subprocess
import shutil
from typing import Dict, List, Optional
from pathlib import Path
from core.ui import console, log_info, log_success, log_warning, log_error
from core.logger import save_loot
from rich.table import Table
from rich.panel import Panel

# Template categories available in Nuclei
TEMPLATE_CATEGORIES = [
    "cves",           # Known CVEs
    "vulnerabilities", # Generic vulnerabilities  
    "exposures",      # Sensitive data exposures
    "misconfiguration", # Misconfigurations
    "technologies",   # Technology detection
    "takeovers",      # Subdomain takeovers
    "file",           # Sensitive files
    "fuzzing",        # Fuzzing templates
    "headless",       # Headless browser templates
    "workflows",      # Workflow templates
]

# Severity levels
SEVERITIES = ["critical", "high", "medium", "low", "info"]


def check_nuclei_installed() -> bool:
    """Check if nuclei is installed and available."""
    return shutil.which("nuclei") is not None


def parse_nuclei_output(output: str) -> List[Dict]:
    """Parse Nuclei JSON output into findings list."""
    findings = []
    
    for line in output.strip().split('\n'):
        if not line:
            continue
        try:
            finding = json.loads(line)
            findings.append({
                "template_id": finding.get("template-id", "unknown"),
                "name": finding.get("info", {}).get("name", "Unknown"),
                "severity": finding.get("info", {}).get("severity", "info"),
                "matched_at": finding.get("matched-at", ""),
                "type": finding.get("type", "http"),
                "host": finding.get("host", ""),
                "description": finding.get("info", {}).get("description", ""),
                "tags": finding.get("info", {}).get("tags", []),
                "reference": finding.get("info", {}).get("reference", []),
                "extracted_results": finding.get("extracted-results", []),
                "matcher_name": finding.get("matcher-name", ""),
            })
        except json.JSONDecodeError:
            # Non-JSON line (progress output, etc)
            pass
    
    return findings


def run_nuclei_scan(
    target: str,
    templates: str = "cves,exposures,misconfiguration",
    severity: str = "critical,high,medium",
    threads: int = 25,
    rate_limit: int = 150,
    timeout: int = 10,
    silent: bool = False
) -> List[Dict]:
    """
    Run Nuclei scan on target.
    
    Args:
        target: Target URL or file with URLs
        templates: Comma-separated template categories
        severity: Comma-separated severity levels
        threads: Number of concurrent threads
        rate_limit: Requests per second
        timeout: Timeout in seconds
        silent: Suppress banner/progress
        
    Returns:
        List of findings
    """
    console.print(f"\n[bold magenta][*] NUCLEI SCAN[/bold magenta] -> [yellow]{target}[/yellow]")
    
    # Check if nuclei is installed
    if not check_nuclei_installed():
        log_error("Nuclei not found in PATH!")
        console.print("[yellow]Install Nuclei:[/yellow]")
        console.print("  go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
        console.print("  OR download from: https://github.com/projectdiscovery/nuclei/releases")
        return []
    
    # Build command
    cmd = [
        "nuclei",
        "-u", target,
        "-j",  # JSON output
        "-nc",  # No color
        "-silent",
    ]
    
    # Add template categories
    if templates:
        for cat in templates.split(','):
            cat = cat.strip()
            if cat in TEMPLATE_CATEGORIES:
                cmd.extend(["-t", cat])
    
    # Add severity filter
    if severity:
        cmd.extend(["-severity", severity])
    
    # Performance options
    cmd.extend(["-c", str(threads)])
    cmd.extend(["-rl", str(rate_limit)])
    cmd.extend(["-timeout", str(timeout)])
    
    log_info(f"Running: {' '.join(cmd[:6])}...")
    log_info(f"Templates: {templates}")
    log_info(f"Severity: {severity}")
    
    try:
        # Run nuclei
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600  # 10 minute max
        )
        
        # Parse output
        findings = parse_nuclei_output(result.stdout)
        
        if findings:
            log_success(f"Found {len(findings)} vulnerabilities!")
            
            # Group by severity
            critical = [f for f in findings if f["severity"] == "critical"]
            high = [f for f in findings if f["severity"] == "high"]
            medium = [f for f in findings if f["severity"] == "medium"]
            low = [f for f in findings if f["severity"] == "low"]
            info = [f for f in findings if f["severity"] == "info"]
            
            # Display summary
            console.print(f"\n[bold]Severity Breakdown:[/bold]")
            if critical:
                console.print(f"  [bold red]CRITICAL: {len(critical)}[/bold red]")
            if high:
                console.print(f"  [red]HIGH: {len(high)}[/red]")
            if medium:
                console.print(f"  [yellow]MEDIUM: {len(medium)}[/yellow]")
            if low:
                console.print(f"  [blue]LOW: {len(low)}[/blue]")
            if info:
                console.print(f"  [dim]INFO: {len(info)}[/dim]")
            
            # Display critical/high findings
            important = critical + high
            if important:
                console.print(Panel(
                    "\n".join([
                        f"[{f['severity'].upper()}] {f['name']}\n  → {f['matched_at'][:60]}"
                        for f in important[:10]
                    ]),
                    title="[bold red]⚠ Critical/High Findings[/bold red]",
                    border_style="red"
                ))
            
            # Full table
            table = Table(title="All Findings", border_style="cyan")
            table.add_column("Severity", width=10)
            table.add_column("Template", width=25)
            table.add_column("Name", width=30)
            table.add_column("Match", width=40)
            
            for f in findings[:20]:  # Limit display
                sev = f["severity"]
                if sev == "critical":
                    sev_style = "[bold red]CRITICAL[/bold red]"
                elif sev == "high":
                    sev_style = "[red]HIGH[/red]"
                elif sev == "medium":
                    sev_style = "[yellow]MEDIUM[/yellow]"
                elif sev == "low":
                    sev_style = "[blue]LOW[/blue]"
                else:
                    sev_style = "[dim]INFO[/dim]"
                
                table.add_row(
                    sev_style,
                    f["template_id"][:25],
                    f["name"][:30],
                    f["matched_at"][:40] + "..." if len(f["matched_at"]) > 40 else f["matched_at"]
                )
            
            if len(findings) > 20:
                console.print(f"[dim]... and {len(findings) - 20} more findings[/dim]")
            
            console.print(table)
            
            # Save to loot
            save_loot("nuclei", target, {
                "total": len(findings),
                "critical": len(critical),
                "high": len(high),
                "medium": len(medium),
                "low": len(low),
                "info": len(info),
                "findings": findings
            })
        else:
            log_info("No vulnerabilities found")
            if result.stderr:
                # Check for common errors
                if "no templates" in result.stderr.lower():
                    log_warning("No templates found. Run: nuclei -update-templates")
        
        return findings
        
    except subprocess.TimeoutExpired:
        log_error("Nuclei scan timed out (10 min limit)")
        return []
    except Exception as e:
        log_error(f"Nuclei execution failed: {e}")
        return []
