# HikariSystem Tsurugi/core/workflow.py
"""
Bug Bounty Workflow Engine
Inspired by HexStrike's Bug Bounty Workflow Manager.

Features:
- Automated recon → scan → exploit pipeline
- Checkpoint/resume capability
- Parallel execution where possible
- Progress tracking
"""

import json
import time
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass, field, asdict
from pathlib import Path

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.panel import Panel
from rich.table import Table

console = Console()

# Workflow state directory
WORKFLOW_DIR = Path(__file__).parent.parent / "loot" / "workflows"
WORKFLOW_DIR.mkdir(parents=True, exist_ok=True)


class StageStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class WorkflowStage:
    """A single stage in the workflow."""
    name: str
    description: str
    status: StageStatus = StageStatus.PENDING
    started_at: str = None
    completed_at: str = None
    results: Dict = field(default_factory=dict)
    error: str = None


@dataclass
class WorkflowState:
    """Complete workflow state."""
    id: str
    target: str
    scope: str
    created_at: str
    updated_at: str
    current_stage: int = 0
    stages: List[WorkflowStage] = field(default_factory=list)
    findings: List[Dict] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "id": self.id,
            "target": self.target,
            "scope": self.scope,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "current_stage": self.current_stage,
            "stages": [
                {
                    "name": s.name,
                    "description": s.description,
                    "status": s.status.value,
                    "started_at": s.started_at,
                    "completed_at": s.completed_at,
                    "results": s.results,
                    "error": s.error
                }
                for s in self.stages
            ],
            "findings": self.findings
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> "WorkflowState":
        """Create from dictionary."""
        stages = [
            WorkflowStage(
                name=s["name"],
                description=s["description"],
                status=StageStatus(s["status"]),
                started_at=s.get("started_at"),
                completed_at=s.get("completed_at"),
                results=s.get("results", {}),
                error=s.get("error")
            )
            for s in data.get("stages", [])
        ]
        return cls(
            id=data["id"],
            target=data["target"],
            scope=data.get("scope", "*"),
            created_at=data["created_at"],
            updated_at=data["updated_at"],
            current_stage=data.get("current_stage", 0),
            stages=stages,
            findings=data.get("findings", [])
        )


class BugBountyWorkflow:
    """
    Automated Bug Bounty Workflow Engine.
    
    Stages:
    1. Subdomain Enumeration
    2. Live Host Detection
    3. Technology Detection
    4. CVE Intelligence
    5. Vulnerability Scanning
    6. Report Generation
    """
    
    STAGES = [
        ("subdomain_enum", "Subdomain Enumeration"),
        ("live_detection", "Live Host Detection"),
        ("tech_detect", "Technology Detection"),
        ("cve_intel", "CVE Intelligence"),
        ("vuln_scan", "Vulnerability Scanning"),
        ("report_gen", "Report Generation"),
    ]
    
    def __init__(self, target: str, scope: str = None, resume_id: str = None):
        self.target = target
        self.scope = scope or f"*.{target}"
        
        if resume_id:
            self.state = self._load_state(resume_id)
            if not self.state:
                raise ValueError(f"Workflow {resume_id} not found")
        else:
            self.state = self._create_new_state()
    
    def _create_new_state(self) -> WorkflowState:
        """Create a new workflow state."""
        workflow_id = f"{self.target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        now = datetime.now().isoformat()
        
        stages = [
            WorkflowStage(name=name, description=desc)
            for name, desc in self.STAGES
        ]
        
        return WorkflowState(
            id=workflow_id,
            target=self.target,
            scope=self.scope,
            created_at=now,
            updated_at=now,
            stages=stages
        )
    
    def _get_state_path(self, workflow_id: str) -> Path:
        """Get path to workflow state file."""
        return WORKFLOW_DIR / f"{workflow_id}.json"
    
    def _save_state(self):
        """Save current workflow state."""
        self.state.updated_at = datetime.now().isoformat()
        path = self._get_state_path(self.state.id)
        with open(path, "w") as f:
            json.dump(self.state.to_dict(), f, indent=2)
    
    def _load_state(self, workflow_id: str) -> Optional[WorkflowState]:
        """Load workflow state from file."""
        path = self._get_state_path(workflow_id)
        if not path.exists():
            return None
        
        with open(path, "r") as f:
            data = json.load(f)
            return WorkflowState.from_dict(data)
    
    def _update_stage(self, stage_idx: int, status: StageStatus, 
                      results: Dict = None, error: str = None):
        """Update a stage status."""
        stage = self.state.stages[stage_idx]
        stage.status = status
        
        if status == StageStatus.RUNNING:
            stage.started_at = datetime.now().isoformat()
        elif status in [StageStatus.COMPLETED, StageStatus.FAILED]:
            stage.completed_at = datetime.now().isoformat()
        
        if results:
            stage.results = results
        if error:
            stage.error = error
        
        self._save_state()
    
    def print_status(self):
        """Print current workflow status."""
        table = Table(title=f"Workflow: {self.state.target}", show_header=True)
        table.add_column("#", style="cyan", width=3)
        table.add_column("Stage", width=25)
        table.add_column("Status", width=12)
        table.add_column("Details", width=40)
        
        for i, stage in enumerate(self.state.stages):
            status_style = {
                StageStatus.PENDING: "white",
                StageStatus.RUNNING: "yellow",
                StageStatus.COMPLETED: "green",
                StageStatus.FAILED: "red",
                StageStatus.SKIPPED: "dim",
            }.get(stage.status, "white")
            
            details = ""
            if stage.results:
                # Show summary of results
                if "count" in stage.results:
                    details = f"Found: {stage.results['count']}"
                elif "items" in stage.results:
                    details = f"Found: {len(stage.results['items'])}"
            if stage.error:
                details = f"Error: {stage.error[:35]}..."
            
            table.add_row(
                str(i + 1),
                stage.description,
                f"[{status_style}]{stage.status.value}[/]",
                details
            )
        
        console.print(table)
        
        # Findings summary
        if self.state.findings:
            console.print(Panel(
                f"[green]Total Findings: {len(self.state.findings)}[/green]",
                title="Findings",
                border_style="green"
            ))
    
    def run(self, stages_to_run: List[str] = None):
        """
        Run the workflow.
        
        Args:
            stages_to_run: Optional list of specific stages to run
        """
        console.print(Panel.fit(
            f"[cyan]Bug Bounty Autopilot[/cyan]\n"
            f"Target: [white]{self.target}[/white]\n"
            f"Scope: [white]{self.scope}[/white]\n"
            f"Workflow ID: [dim]{self.state.id}[/dim]",
            title="TSURUGI AUTOPILOT",
            border_style="magenta"
        ))
        
        # Find first incomplete stage
        start_idx = 0
        for i, stage in enumerate(self.state.stages):
            if stage.status not in [StageStatus.COMPLETED, StageStatus.SKIPPED]:
                start_idx = i
                break
        
        console.print(f"\n[cyan][*] Resuming from stage {start_idx + 1}: {self.state.stages[start_idx].description}[/cyan]")
        
        # Run stages
        for i in range(start_idx, len(self.state.stages)):
            stage = self.state.stages[i]
            
            # Skip if specific stages requested
            if stages_to_run and stage.name not in stages_to_run:
                self._update_stage(i, StageStatus.SKIPPED)
                continue
            
            console.print(f"\n[yellow][>] Stage {i + 1}/{len(self.state.stages)}: {stage.description}[/yellow]")
            self._update_stage(i, StageStatus.RUNNING)
            self.state.current_stage = i
            
            try:
                # Run the stage
                results = self._run_stage(stage.name)
                self._update_stage(i, StageStatus.COMPLETED, results=results)
                console.print(f"[green][+] {stage.description} completed[/green]")
                
            except Exception as e:
                self._update_stage(i, StageStatus.FAILED, error=str(e))
                console.print(f"[red][!] {stage.description} failed: {e}[/red]")
                
                # Ask to continue
                # For now, we'll continue automatically
                console.print("[yellow][!] Continuing to next stage...[/yellow]")
        
        # Final summary
        console.print("\n")
        self.print_status()
        console.print(f"\n[green][+] Workflow completed! Results saved to: {self._get_state_path(self.state.id)}[/green]")
    
    def _run_stage(self, stage_name: str) -> Dict:
        """Run a specific stage and return results."""
        
        if stage_name == "subdomain_enum":
            return self._stage_subdomain_enum()
        elif stage_name == "live_detection":
            return self._stage_live_detection()
        elif stage_name == "tech_detect":
            return self._stage_tech_detect()
        elif stage_name == "cve_intel":
            return self._stage_cve_intel()
        elif stage_name == "vuln_scan":
            return self._stage_vuln_scan()
        elif stage_name == "report_gen":
            return self._stage_report_gen()
        else:
            raise ValueError(f"Unknown stage: {stage_name}")
    
    def _stage_subdomain_enum(self) -> Dict:
        """Stage 1: Subdomain enumeration."""
        from modules.crawler import crawl_target
        
        subdomains = []
        
        # Try to find subdomains via crawling
        console.print("  [*] Crawling for subdomains...")
        try:
            result = crawl_target(f"https://{self.target}", depth=2, fast=True)
            
            # Extract unique subdomains from crawl result
            import re
            from urllib.parse import urlparse
            
            # Get links from the result
            links = result.get("get_endpoints", []) + result.get("api_endpoints", [])
            
            for link in links:
                parsed = urlparse(link)
                if parsed.netloc and self.target in parsed.netloc:
                    if parsed.netloc not in subdomains:
                        subdomains.append(parsed.netloc)
        except Exception as e:
            console.print(f"  [!] Crawl error: {e}")
        
        # Add main domain
        if self.target not in subdomains:
            subdomains.insert(0, self.target)
        
        console.print(f"  [+] Found {len(subdomains)} domains")
        
        return {"count": len(subdomains), "items": subdomains}
    
    def _stage_live_detection(self) -> Dict:
        """Stage 2: Detect live hosts."""
        from core.requester import TsurugiSession
        
        subdomains = self.state.stages[0].results.get("items", [self.target])
        live_hosts = []
        
        console.print(f"  [*] Checking {len(subdomains)} hosts...")
        
        requester = TsurugiSession()
        
        for domain in subdomains:
            for protocol in ["https", "http"]:
                url = f"{protocol}://{domain}"
                try:
                    resp = requester.get(url, timeout=5)
                    if resp and resp.status_code < 500:
                        live_hosts.append({
                            "url": url,
                            "status": resp.status_code
                        })
                        console.print(f"  [+] {url} - {resp.status_code}")
                        break
                except:
                    pass
        
        return {"count": len(live_hosts), "items": live_hosts}
    
    def _stage_tech_detect(self) -> Dict:
        """Stage 3: Technology detection."""
        from modules.headers import check_security_headers
        
        live_hosts = self.state.stages[1].results.get("items", [])
        technologies = {}
        
        for host in live_hosts[:10]:  # Limit to first 10
            url = host.get("url", host) if isinstance(host, dict) else host
            console.print(f"  [*] Analyzing {url}...")
            
            try:
                results = check_security_headers(url)
                if results and not results.get("error"):
                    # Extract technology info from headers
                    dangerous = results.get("dangerous", {})
                    technologies[url] = {
                        "server": dangerous.get("Server", {}).get("value", ""),
                        "powered_by": dangerous.get("X-Powered-By", {}).get("value", ""),
                        "framework": "",
                    }
            except Exception as e:
                console.print(f"  [!] Error: {e}")
        
        return {"count": len(technologies), "items": technologies}
    
    def _stage_cve_intel(self) -> Dict:
        """Stage 4: CVE Intelligence lookup."""
        from modules.cve_intel import CVEIntelligence
        
        technologies = self.state.stages[2].results.get("items", {})
        all_cves = []
        
        intel = CVEIntelligence()
        
        # Extract unique technologies
        tech_set = set()
        for url, tech in technologies.items():
            if tech.get("server"):
                tech_set.add(tech["server"].split("/")[0])
            if tech.get("powered_by"):
                tech_set.add(tech["powered_by"])
        
        for tech in tech_set:
            console.print(f"  [*] Searching CVEs for {tech}...")
            cves = intel.search_cves(tech, limit=5)
            
            for cve in cves:
                if cve.severity in ["CRITICAL", "HIGH"]:
                    all_cves.append({
                        "id": cve.id,
                        "severity": cve.severity,
                        "score": cve.cvss_score,
                        "tech": tech
                    })
                    self.state.findings.append({
                        "type": "cve",
                        "cve_id": cve.id,
                        "severity": cve.severity,
                        "technology": tech
                    })
        
        self._save_state()
        
        return {"count": len(all_cves), "items": all_cves}
    
    def _stage_vuln_scan(self) -> Dict:
        """Stage 5: Vulnerability scanning."""
        # Skip XSS scan for now - just log info
        live_hosts = self.state.stages[1].results.get("items", [])
        vulns = []
        
        for host in live_hosts[:5]:  # Limit
            url = host.get("url", host) if isinstance(host, dict) else host
            console.print(f"  [*] Logged for manual scan: {url}")
            # Add as potential target to investigate
            self.state.findings.append({
                "type": "target",
                "url": url,
                "note": "Needs manual XSS/SQLi testing"
            })
        
        self._save_state()
        
        return {"count": len(vulns), "items": vulns}
    
    def _stage_report_gen(self) -> Dict:
        """Stage 6: Generate report."""
        from datetime import datetime
        
        # Generate simple report
        report_path = WORKFLOW_DIR / f"{self.state.id}_report.md"
        
        with open(report_path, "w") as f:
            f.write(f"# Tsurugi Autopilot Report\n\n")
            f.write(f"**Target:** {self.target}\n")
            f.write(f"**Scope:** {self.scope}\n")
            f.write(f"**Generated:** {datetime.now().isoformat()}\n\n")
            
            f.write(f"\n## Findings ({len(self.state.findings)})\n\n")
            for finding in self.state.findings:
                f.write(f"- **{finding.get('type', 'unknown')}**: {finding}\n")
        
        console.print(f"  [+] Report saved: {report_path}")
        
        return {"report_path": str(report_path)}
        
        console.print(f"  [+] Report saved: {report_path}")
        
        return {"report_path": str(report_path)}


def run_autopilot(target: str, scope: str = None, resume_id: str = None):
    """
    Run the Bug Bounty Autopilot workflow.
    
    Args:
        target: Target domain (e.g., target.com)
        scope: Scope pattern (e.g., *.target.com)
        resume_id: Optional workflow ID to resume
    """
    workflow = BugBountyWorkflow(target, scope, resume_id)
    workflow.run()
