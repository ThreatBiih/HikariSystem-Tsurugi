import subprocess
import shutil
import re
from core.ui import console, log_info, log_error, log_success

def check_nmap_installed():
    return shutil.which("nmap") is not None

def run_nmap_scan(target: str):
    """
    Runs a fast service scan using Nmap and returns a list of open ports and services.
    """
    if not check_nmap_installed():
        log_error("Nmap is not installed or not in PATH. Please install Nmap.")
        return []

    console.print(f"\n[bold red]🗡️ TSURUGI RECON MODULE[/bold red] -> [yellow]{target}[/yellow]")
    log_info("Executing Nmap Service Scan (T4)... This might take a moment.")

    # Command: nmap -sV -T4 -F <target> (Fast scan top 100 ports + Version)
    # Using -oG - to parse greppable output easily
    cmd = ["nmap", "-sV", "-T4", "-F", "-oG", "-", target]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        output = result.stdout
        
        # Simple parsing logic related to Nmap Grep output
        # Host: 127.0.0.1 ()	Ports: 22/open/tcp//ssh//OpenSSH 8.2p1/, 80/open/tcp//http//Apache httpd/
        
        services = []
        for line in output.splitlines():
            if "Ports:" in line:
                # Extract the ports section
                ports_part = line.split("Ports:")[1].strip()
                # Split by comma to get individual port entries
                for port_entry in ports_part.split(","):
                    # Format: 80/open/tcp//http//Apache httpd/
                    parts = port_entry.strip().split("/")
                    if len(parts) >= 5 and parts[1] == "open":
                        port_num = parts[0]
                        service_name = parts[4]
                        version = parts[6] if len(parts) > 6 else ""
                        
                        services.append({
                            "port": port_num,
                            "service": service_name,
                            "version": version
                        })
                        console.print(f"  └── [green]Open Port: {port_num}[/green] ({service_name}) {version}")

        if not services:
            log_info("No open ports found or host is down.")
            
        return services

    except subprocess.TimeoutExpired:
        log_error("Nmap scan timed out.")
        return []
    except Exception as e:
        log_error(f"Failed to run Nmap: {e}")
        return []

def analyze_services(target: str, services: list):
    """
    Analyzes found services and triggers/suggests specific modules.
    """
    targets_for_web = []

    for s in services:
        port = s['port']
        service = s['service'].lower()

        if "http" in service or port in ["80", "443", "8080", "8000"]:
            protocol = "https" if "ssl" in service or port == "443" else "http"
            url = f"{protocol}://{target}:{port}"
            targets_for_web.append(url)
            console.print(f"[bold yellow]⚡ TRIGGER:[/bold yellow] Web Service detected on {port}. Suggesting SQLi/LFI scan.")

    return targets_for_web
