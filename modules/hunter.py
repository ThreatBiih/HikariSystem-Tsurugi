import subprocess
import shutil
import os
from core.ui import console, log_info, log_error, log_success, log_warning

def check_tool(tool_name):
    """Checks if a tool is available in PATH."""
    return shutil.which(tool_name) is not None

def run_hunter_protocol(domain: str, full_scan: bool = False):
    """
    Executes the full Hunter Protocol:
    1. Subdomain Enumeration (subfinder)
    2. Liveness Check (httpx - PD Version)
    3. Vulnerability Scanning (nuclei)
    """
    console.print(f"\n[bold red]🗡️ TSURUGI HUNTER PROTOCOL[/bold red] -> [yellow]{domain}[/yellow]")

    # Check dependencies
    # Note: We specifically look for the go versions commonly used in bounty
    tools = ["subfinder", "nuclei"] 
    missing = [t for t in tools if not check_tool(t)]
    
    if missing:
        log_error(f"Missing external tools: {', '.join(missing)}")
        console.print("[yellow]To use Hunter Protocol, you need to install the ProjectDiscovery stack:[/yellow]")
        console.print("  [dim]go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest[/dim]")
        # console.print("  [dim]go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest[/dim]") # Warning: conflict with python httpx
        console.print("  [dim]go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest[/dim]")
        return

    # 1. Subfinder
    log_info("Phase 1: Subdomain Enumeration (Subfinder)")
    subs_file = f"{domain}_subs.txt"
    try:
        cmd_sub = ["subfinder", "-d", domain, "-o", subs_file, "-silent"]
        subprocess.run(cmd_sub, check=True)
        
        # Count results
        with open(subs_file, 'r') as f:
            count = sum(1 for _ in f)
        log_success(f"Found {count} subdomains.")
        
    except Exception as e:
        log_error(f"Subfinder failed: {e}")
        return

    # 2. Nuclei (Scanning the subdomains found)
    log_info("Phase 2: Vulnerability Scanning (Nuclei)")
    # We run nuclei directly on the subdomains file. Nuclei handles liveness checks internally effectively enough for this level.
    
    nuclei_out = f"{domain}_nuclei.txt"
    severity = "critical,high" if not full_scan else "critical,high,medium,low"
    
    try:
        # Command: nuclei -l subs.txt -s critical,high -o output.txt
        cmd_nuc = ["nuclei", "-l", subs_file, "-s", severity, "-o", nuclei_out]
        
        console.print(f"  └── Running Nuclei with severity: [bold]{severity}[/bold]...")
        process = subprocess.Popen(cmd_nuc, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        # Real-time output feedback could be added here, for now we wait
        stdout, stderr = process.communicate()
        
        if process.returncode == 0:
            log_success("Nuclei scan completed.")
            if os.path.exists(nuclei_out):
                console.print(f"[bold green]Results saved to {nuclei_out}[/bold green]")
                # Display findings
                with open(nuclei_out, 'r') as f:
                    for line in f:
                        console.print(line.strip())
            else:
                log_info("No vulnerabilities found.")
        else:
            log_error(f"Nuclei error: {stderr}")

    except Exception as e:
        log_error(f"Nuclei execution failed: {e}")

    # Cleanup (Optional, maybe keep for user)
    # os.remove(subs_file)
