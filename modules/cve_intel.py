# HikariSystem Tsurugi/modules/cve_intel.py
"""
CVE Intelligence Module
Inspired by HexStrike's CVE Intelligence Manager.

Features:
- NVD API integration for CVE lookup
- Local caching to reduce API calls
- Technology to CVE mapping
- CVSS severity scoring
"""

import json
import os
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from dataclasses import dataclass
from pathlib import Path

import httpx
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

# Cache directory
CACHE_DIR = Path(__file__).parent.parent / "loot" / "cve_cache"
CACHE_DIR.mkdir(parents=True, exist_ok=True)

# NVD API (no key needed for basic queries, but rate limited)
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Common technology keywords mapping
TECH_KEYWORDS = {
    "wordpress": ["wordpress", "wp-"],
    "apache": ["apache", "httpd"],
    "nginx": ["nginx"],
    "php": ["php"],
    "mysql": ["mysql", "mariadb"],
    "jquery": ["jquery"],
    "react": ["react", "reactjs"],
    "node": ["node.js", "nodejs", "node"],
    "django": ["django"],
    "flask": ["flask"],
    "laravel": ["laravel"],
    "drupal": ["drupal"],
    "joomla": ["joomla"],
    "tomcat": ["tomcat"],
    "jenkins": ["jenkins"],
    "gitlab": ["gitlab"],
    "grafana": ["grafana"],
    "elasticsearch": ["elasticsearch", "elastic"],
    "redis": ["redis"],
    "mongodb": ["mongodb", "mongo"],
    "postgres": ["postgresql", "postgres"],
    "docker": ["docker"],
    "kubernetes": ["kubernetes", "k8s"],
}


@dataclass
class CVE:
    """Represents a CVE entry."""
    id: str
    description: str
    severity: str
    cvss_score: float
    published: str
    references: List[str]
    exploits_available: bool = False


class CVEIntelligence:
    """CVE Intelligence Engine - Query and cache CVE data."""
    
    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.environ.get("NVD_API_KEY")
        self.cache_ttl = timedelta(hours=24)  # Cache for 24 hours
        
    def _get_cache_path(self, keyword: str, version: str = None) -> Path:
        """Get cache file path for a query."""
        cache_key = f"{keyword}_{version or 'any'}".lower().replace(" ", "_")
        return CACHE_DIR / f"{cache_key}.json"
    
    def _is_cache_valid(self, cache_path: Path) -> bool:
        """Check if cache is still valid."""
        if not cache_path.exists():
            return False
        
        mtime = datetime.fromtimestamp(cache_path.stat().st_mtime)
        return datetime.now() - mtime < self.cache_ttl
    
    def _load_cache(self, cache_path: Path) -> Optional[List[CVE]]:
        """Load CVEs from cache."""
        if not self._is_cache_valid(cache_path):
            return None
        
        try:
            with open(cache_path, "r") as f:
                data = json.load(f)
                return [CVE(**item) for item in data]
        except Exception:
            return None
    
    def _save_cache(self, cache_path: Path, cves: List[CVE]):
        """Save CVEs to cache."""
        try:
            with open(cache_path, "w") as f:
                data = [vars(cve) for cve in cves]
                json.dump(data, f, indent=2)
        except Exception as e:
            console.print(f"[yellow][!] Cache save failed: {e}[/yellow]")
    
    def search_cves(self, keyword: str, version: str = None, 
                    limit: int = 20, severity_filter: str = None) -> List[CVE]:
        """
        Search for CVEs by keyword and optional version.
        
        Args:
            keyword: Technology name (e.g., "wordpress", "apache")
            version: Optional version (e.g., "6.0", "2.4.51")
            limit: Maximum CVEs to return
            severity_filter: Filter by severity (CRITICAL, HIGH, MEDIUM, LOW)
        
        Returns:
            List of CVE objects
        """
        cache_path = self._get_cache_path(keyword, version)
        
        # Check cache first
        cached = self._load_cache(cache_path)
        if cached:
            console.print(f"[cyan][*] Using cached CVE data for {keyword}[/cyan]")
            cves = cached
        else:
            console.print(f"[cyan][*] Querying NVD API for {keyword}...[/cyan]")
            cves = self._query_nvd(keyword, version, limit)
            if cves:
                self._save_cache(cache_path, cves)
        
        # Apply severity filter
        if severity_filter and cves:
            cves = [c for c in cves if c.severity.upper() == severity_filter.upper()]
        
        return cves[:limit]
    
    def _query_nvd(self, keyword: str, version: str = None, limit: int = 20) -> List[CVE]:
        """Query the NVD API for CVEs."""
        cves = []
        
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": min(limit, 50),
        }
        
        if version:
            params["keywordSearch"] = f"{keyword} {version}"
        
        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key
        
        try:
            with httpx.Client(timeout=30) as client:
                response = client.get(NVD_API_URL, params=params, headers=headers)
                response.raise_for_status()
                data = response.json()
        except httpx.TimeoutException:
            console.print("[red][!] NVD API timeout[/red]")
            return []
        except httpx.HTTPStatusError as e:
            console.print(f"[red][!] NVD API error: {e.response.status_code}[/red]")
            return []
        except Exception as e:
            console.print(f"[red][!] NVD API request failed: {e}[/red]")
            return []
        
        # Parse vulnerabilities
        vulnerabilities = data.get("vulnerabilities", [])
        
        for vuln in vulnerabilities:
            cve_data = vuln.get("cve", {})
            cve_id = cve_data.get("id", "")
            
            # Get description
            descriptions = cve_data.get("descriptions", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")[:500]
                    break
            
            # Get CVSS score and severity
            metrics = cve_data.get("metrics", {})
            cvss_score = 0.0
            severity = "UNKNOWN"
            
            # Try CVSS 3.1 first, then 3.0, then 2.0
            for cvss_version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if cvss_version in metrics:
                    cvss_data = metrics[cvss_version][0]
                    if "cvssData" in cvss_data:
                        cvss_score = cvss_data["cvssData"].get("baseScore", 0.0)
                        severity = cvss_data["cvssData"].get("baseSeverity", "UNKNOWN")
                    break
            
            # Get references
            references = []
            for ref in cve_data.get("references", [])[:5]:
                references.append(ref.get("url", ""))
            
            # Check for exploit references
            exploits_available = any(
                "exploit" in ref.lower() or "poc" in ref.lower()
                for ref in references
            )
            
            # Get published date
            published = cve_data.get("published", "")[:10]
            
            cve = CVE(
                id=cve_id,
                description=description,
                severity=severity,
                cvss_score=cvss_score,
                published=published,
                references=references,
                exploits_available=exploits_available
            )
            cves.append(cve)
        
        # Sort by CVSS score descending
        cves.sort(key=lambda x: x.cvss_score, reverse=True)
        
        return cves
    
    def lookup_by_technology(self, tech_name: str, version: str = None) -> List[CVE]:
        """
        Lookup CVEs for a detected technology.
        Maps common tech names to search keywords.
        """
        # Normalize tech name
        tech_lower = tech_name.lower()
        
        # Find matching keywords
        search_keyword = tech_lower
        for key, variations in TECH_KEYWORDS.items():
            if any(v in tech_lower for v in variations):
                search_keyword = key
                break
        
        return self.search_cves(search_keyword, version)


def print_cve_table(cves: List[CVE], title: str = "CVE Intelligence Results"):
    """Print CVEs in a nice table format."""
    if not cves:
        console.print("[yellow][!] No CVEs found[/yellow]")
        return
    
    table = Table(title=title, show_header=True, header_style="bold cyan")
    table.add_column("CVE ID", style="white", width=18)
    table.add_column("Severity", width=10)
    table.add_column("CVSS", width=6)
    table.add_column("Published", width=12)
    table.add_column("Description", width=60)
    
    for cve in cves:
        # Color severity
        if cve.severity == "CRITICAL":
            sev_style = "[bold red]"
        elif cve.severity == "HIGH":
            sev_style = "[red]"
        elif cve.severity == "MEDIUM":
            sev_style = "[yellow]"
        else:
            sev_style = "[white]"
        
        # Truncate description
        desc = cve.description[:57] + "..." if len(cve.description) > 60 else cve.description
        
        # Add exploit indicator
        cve_id = cve.id
        if cve.exploits_available:
            cve_id += " [red][!][/red]"
        
        table.add_row(
            cve_id,
            f"{sev_style}{cve.severity}[/]",
            f"{cve.cvss_score:.1f}",
            cve.published,
            desc
        )
    
    console.print(table)
    
    # Summary
    critical = len([c for c in cves if c.severity == "CRITICAL"])
    high = len([c for c in cves if c.severity == "HIGH"])
    exploits = len([c for c in cves if c.exploits_available])
    
    if critical > 0 or high > 0:
        console.print(Panel(
            f"[red]CRITICAL: {critical}[/red] | [yellow]HIGH: {high}[/yellow] | "
            f"[magenta]Exploits Available: {exploits}[/magenta]",
            title="Summary",
            border_style="red" if critical > 0 else "yellow"
        ))


def run_cve_lookup(keyword: str, version: str = None, 
                   limit: int = 10, severity: str = None):
    """
    Run CVE lookup from CLI.
    
    Args:
        keyword: Technology to search (e.g., wordpress, apache)
        version: Optional version number
        limit: Max results to show
        severity: Filter by severity level
    """
    console.print(Panel.fit(
        f"[cyan]CVE Intelligence Lookup[/cyan]\n"
        f"Technology: [white]{keyword}[/white]\n"
        f"Version: [white]{version or 'any'}[/white]",
        border_style="cyan"
    ))
    
    intel = CVEIntelligence()
    cves = intel.search_cves(keyword, version, limit, severity)
    
    print_cve_table(cves, f"CVEs for {keyword} {version or ''}")
    
    return cves
