# HikariSystem Tsurugi/modules/domxss.py
"""
DOM XSS DETECTION MODULE
Static analysis of JavaScript to find DOM-based XSS vulnerabilities
Detects dangerous sinks and traces user-controlled sources
"""
import re
from typing import Dict, List, Set, Tuple
from urllib.parse import urlparse
from core.ui import console, log_info, log_success, log_warning, log_error
from core.requester import TsurugiSession
from core.logger import save_loot
from rich.table import Table
from rich.panel import Panel

# Dangerous sinks that can lead to DOM XSS
SINKS = {
    # HTML injection sinks
    "innerHTML": {"severity": "high", "category": "html_injection"},
    "outerHTML": {"severity": "high", "category": "html_injection"},
    "insertAdjacentHTML": {"severity": "high", "category": "html_injection"},
    "document.write": {"severity": "critical", "category": "html_injection"},
    "document.writeln": {"severity": "critical", "category": "html_injection"},
    
    # Script execution sinks
    "eval": {"severity": "critical", "category": "code_execution"},
    "Function": {"severity": "critical", "category": "code_execution"},
    "setTimeout": {"severity": "high", "category": "code_execution"},
    "setInterval": {"severity": "high", "category": "code_execution"},
    "setImmediate": {"severity": "high", "category": "code_execution"},
    "execScript": {"severity": "critical", "category": "code_execution"},
    
    # URL/Redirect sinks
    "location": {"severity": "high", "category": "redirect"},
    "location.href": {"severity": "high", "category": "redirect"},
    "location.assign": {"severity": "high", "category": "redirect"},
    "location.replace": {"severity": "high", "category": "redirect"},
    "window.open": {"severity": "medium", "category": "redirect"},
    
    # jQuery sinks
    ".html(": {"severity": "high", "category": "jquery"},
    ".append(": {"severity": "high", "category": "jquery"},
    ".prepend(": {"severity": "high", "category": "jquery"},
    ".after(": {"severity": "high", "category": "jquery"},
    ".before(": {"severity": "high", "category": "jquery"},
    ".replaceWith(": {"severity": "high", "category": "jquery"},
    ".wrap(": {"severity": "medium", "category": "jquery"},
    ".wrapAll(": {"severity": "medium", "category": "jquery"},
    "$.parseHTML(": {"severity": "high", "category": "jquery"},
    
    # DOM manipulation
    "createElement": {"severity": "medium", "category": "dom"},
    "createContextualFragment": {"severity": "high", "category": "dom"},
    "Range.createContextualFragment": {"severity": "high", "category": "dom"},
    
    # Script src modification
    "script.src": {"severity": "critical", "category": "script_injection"},
    "script.text": {"severity": "critical", "category": "script_injection"},
    "script.textContent": {"severity": "critical", "category": "script_injection"},
    "script.innerText": {"severity": "critical", "category": "script_injection"},
}

# User-controllable sources
SOURCES = {
    # URL sources
    "location.search": {"category": "url", "controllability": "high"},
    "location.hash": {"category": "url", "controllability": "high"},
    "location.href": {"category": "url", "controllability": "high"},
    "location.pathname": {"category": "url", "controllability": "medium"},
    "document.URL": {"category": "url", "controllability": "high"},
    "document.documentURI": {"category": "url", "controllability": "high"},
    "document.baseURI": {"category": "url", "controllability": "medium"},
    
    # Referrer
    "document.referrer": {"category": "referrer", "controllability": "high"},
    
    # Storage
    "localStorage": {"category": "storage", "controllability": "medium"},
    "sessionStorage": {"category": "storage", "controllability": "medium"},
    
    # Cookies
    "document.cookie": {"category": "cookie", "controllability": "medium"},
    
    # PostMessage
    "postMessage": {"category": "postmessage", "controllability": "high"},
    "event.data": {"category": "postmessage", "controllability": "high"},
    "e.data": {"category": "postmessage", "controllability": "high"},
    
    # Window name
    "window.name": {"category": "window", "controllability": "high"},
    
    # Input elements
    ".value": {"category": "input", "controllability": "high"},
    "URLSearchParams": {"category": "url", "controllability": "high"},
}


def find_sinks(js_content: str) -> List[Dict]:
    """Find dangerous sinks in JavaScript content."""
    findings = []
    lines = js_content.split('\n')
    
    for line_num, line in enumerate(lines, 1):
        for sink, info in SINKS.items():
            # Create pattern that matches sink usage
            if sink.startswith('.'):
                pattern = re.escape(sink)
            else:
                pattern = r'\b' + re.escape(sink) + r'\b'
            
            matches = list(re.finditer(pattern, line, re.IGNORECASE))
            for match in matches:
                # Get context around the match
                start = max(0, match.start() - 30)
                end = min(len(line), match.end() + 50)
                context = line[start:end].strip()
                
                findings.append({
                    "type": "sink",
                    "sink": sink,
                    "line": line_num,
                    "context": context,
                    "severity": info["severity"],
                    "category": info["category"]
                })
    
    return findings


def find_sources(js_content: str) -> List[Dict]:
    """Find user-controllable sources in JavaScript content."""
    findings = []
    lines = js_content.split('\n')
    
    for line_num, line in enumerate(lines, 1):
        for source, info in SOURCES.items():
            if source.startswith('.'):
                pattern = re.escape(source)
            else:
                pattern = r'\b' + re.escape(source) + r'\b'
            
            matches = list(re.finditer(pattern, line, re.IGNORECASE))
            for match in matches:
                start = max(0, match.start() - 20)
                end = min(len(line), match.end() + 40)
                context = line[start:end].strip()
                
                findings.append({
                    "type": "source",
                    "source": source,
                    "line": line_num,
                    "context": context,
                    "category": info["category"],
                    "controllability": info["controllability"]
                })
    
    return findings


def analyze_for_domxss(js_content: str, source_url: str = None) -> Dict:
    """
    Analyze JavaScript for DOM XSS vulnerabilities.
    
    Returns dict with:
    - sinks: List of dangerous sinks found
    - sources: List of user-controllable sources
    - potential_vulns: Lines where both source and sink appear
    """
    sinks = find_sinks(js_content)
    sources = find_sources(js_content)
    
    # Find potential vulnerabilities (same line has source and sink)
    potential_vulns = []
    sink_lines = {s["line"] for s in sinks}
    source_lines = {s["line"] for s in sources}
    
    # Lines with both
    dangerous_lines = sink_lines.intersection(source_lines)
    
    for line_num in dangerous_lines:
        line_sinks = [s for s in sinks if s["line"] == line_num]
        line_sources = [s for s in sources if s["line"] == line_num]
        
        for sink in line_sinks:
            for source in line_sources:
                potential_vulns.append({
                    "line": line_num,
                    "sink": sink["sink"],
                    "source": source["source"],
                    "sink_severity": sink["severity"],
                    "context": sink["context"],
                    "risk": "high" if sink["severity"] == "critical" else "medium"
                })
    
    return {
        "sinks": sinks,
        "sources": sources,
        "potential_vulns": potential_vulns,
        "source_url": source_url
    }


def run_domxss_scan(url: str, cookie: str = None, proxy: str = None, 
                    headless: bool = False) -> Dict:
    """
    Run DOM XSS analysis on a URL.
    
    Fetches the page and any linked JS files, then analyzes for DOM XSS patterns.
    """
    console.print(f"\n[bold magenta][*] DOM XSS ANALYSIS[/bold magenta] -> [yellow]{url}[/yellow]")
    
    session = TsurugiSession(cookie_string=cookie, proxy=proxy)
    
    # Fetch main page
    log_info("Fetching page content...")
    resp = session.get(url, timeout=15)
    if not resp:
        log_error("Failed to fetch URL")
        return {}
    
    all_results = {
        "url": url,
        "inline_scripts": [],
        "external_scripts": [],
        "total_sinks": 0,
        "total_sources": 0,
        "potential_vulns": []
    }
    
    # Extract inline scripts
    inline_pattern = re.compile(r'<script[^>]*>(.*?)</script>', re.DOTALL | re.IGNORECASE)
    inline_scripts = inline_pattern.findall(resp.text)
    
    log_info(f"Found {len(inline_scripts)} inline scripts")
    
    for i, script in enumerate(inline_scripts):
        if script.strip():
            result = analyze_for_domxss(script, f"{url}#inline-{i}")
            all_results["inline_scripts"].append(result)
            all_results["total_sinks"] += len(result["sinks"])
            all_results["total_sources"] += len(result["sources"])
            all_results["potential_vulns"].extend(result["potential_vulns"])
    
    # Extract external script URLs
    src_pattern = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
    external_srcs = src_pattern.findall(resp.text)
    
    log_info(f"Found {len(external_srcs)} external scripts")
    
    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    
    for src in external_srcs[:10]:  # Limit to 10 external scripts
        # Resolve relative URLs
        if src.startswith('//'):
            script_url = f"{parsed.scheme}:{src}"
        elif src.startswith('/'):
            script_url = f"{base_url}{src}"
        elif not src.startswith('http'):
            script_url = f"{base_url}/{src}"
        else:
            script_url = src
        
        # Skip CDN/known library URLs
        skip_domains = ['cdnjs.cloudflare.com', 'cdn.jsdelivr.net', 'unpkg.com', 
                        'ajax.googleapis.com', 'code.jquery.com']
        if any(d in script_url for d in skip_domains):
            continue
        
        try:
            js_resp = session.get(script_url, timeout=10)
            if js_resp and js_resp.text:
                result = analyze_for_domxss(js_resp.text, script_url)
                all_results["external_scripts"].append(result)
                all_results["total_sinks"] += len(result["sinks"])
                all_results["total_sources"] += len(result["sources"])
                all_results["potential_vulns"].extend(result["potential_vulns"])
        except:
            pass
    
    # Display results
    console.print(f"\n[bold]Analysis Complete[/bold]")
    console.print(f"  Total Sinks: [yellow]{all_results['total_sinks']}[/yellow]")
    console.print(f"  Total Sources: [cyan]{all_results['total_sources']}[/cyan]")
    console.print(f"  Potential Vulns: [red]{len(all_results['potential_vulns'])}[/red]")
    
    if all_results["potential_vulns"]:
        console.print(Panel(
            "\n".join([
                f"Line {v['line']}: {v['source']} → {v['sink']} ({v['risk']})"
                for v in all_results["potential_vulns"][:10]
            ]),
            title="[bold red]⚠ POTENTIAL DOM XSS[/bold red]",
            border_style="red"
        ))
        
        # Save to loot
        save_loot("domxss", url, all_results)
        log_success(f"Found {len(all_results['potential_vulns'])} potential DOM XSS vulnerabilities!")
    else:
        if all_results["total_sinks"] > 0:
            console.print("\n[yellow]Sinks found but no direct source->sink flow detected.[/yellow]")
            console.print("[dim]Manual review recommended for complex data flows.[/dim]")
            
            # Show top sinks
            table = Table(title="Top Dangerous Sinks", border_style="yellow")
            table.add_column("Sink")
            table.add_column("Line")
            table.add_column("Severity")
            table.add_column("Context")
            
            all_sinks = []
            for script in all_results["inline_scripts"] + all_results["external_scripts"]:
                all_sinks.extend(script["sinks"])
            
            # Sort by severity
            severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
            all_sinks.sort(key=lambda x: severity_order.get(x["severity"], 4))
            
            for sink in all_sinks[:10]:
                sev_style = "[red]" if sink["severity"] == "critical" else "[yellow]"
                table.add_row(
                    sink["sink"],
                    str(sink["line"]),
                    f"{sev_style}{sink['severity']}[/{sev_style.strip('[')}",
                    sink["context"][:50] + "..." if len(sink["context"]) > 50 else sink["context"]
                )
            
            console.print(table)
        else:
            log_info("No dangerous sinks found")
    
    return all_results
