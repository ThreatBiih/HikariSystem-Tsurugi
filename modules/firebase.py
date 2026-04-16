# HikariSystem Tsurugi/modules/firebase.py
"""
FIREBASE MISCONFIGURATION SCANNER

Detects:
  1. Exposed firebaseConfig in HTML / JS bundles
  2. Firebase Realtime Database (RTDB) open for anonymous read
  3. Firestore REST anonymous list of root collections
  4. Identity Toolkit anonymous signup enabled (createAuthUri / signupNewUser)
  5. Default Cloud Storage bucket listable without auth

Read-only by design. Never writes. Never authenticates as a real user.
Every finding carries a confidence score and an explicit oracle (what proved it).
"""
import json
import re
from typing import Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse

from rich.panel import Panel
from rich.table import Table

from core.logger import save_loot
from core.requester import TsurugiSession
from core.ui import console, log_error, log_info, log_success, log_warning

# ─────────────────────────────────────────────────────────────────────────────
# Config extraction
# ─────────────────────────────────────────────────────────────────────────────

# Firebase config keys we care about. apiKey + projectId is the minimum useful set.
_CONFIG_KEYS = (
    "apiKey",
    "authDomain",
    "databaseURL",
    "projectId",
    "storageBucket",
    "messagingSenderId",
    "appId",
    "measurementId",
)

# Match key:"value" or key: 'value' inside JS objects. We deliberately do NOT
# match a full JSON object (firebaseConfig may be split across lines, minified,
# or assembled from variables) — instead we sweep each known key.
_KV_PATTERNS = {
    key: re.compile(
        rf"""['"]?{key}['"]?\s*[:=]\s*['"]([^'"\s,}};]+)['"]""",
        re.IGNORECASE,
    )
    for key in _CONFIG_KEYS
}

# Find <script src="..."> for JS bundle harvesting.
_SCRIPT_SRC = re.compile(
    r"""<script[^>]+src\s*=\s*['"]([^'"]+)['"]""", re.IGNORECASE
)

# Cap on JS bundles we'll fetch per scan to keep noise down.
_MAX_BUNDLES = 25
_BUNDLE_TIMEOUT = 15


def _extract_config_from_text(text: str) -> Dict[str, str]:
    """
    Scan a blob of HTML/JS for Firebase config keys.
    Returns whatever was found — caller decides if it's enough.
    """
    found: Dict[str, str] = {}
    for key, pat in _KV_PATTERNS.items():
        m = pat.search(text)
        if m:
            val = m.group(1).strip()
            # Filter obvious template placeholders.
            if val and not val.startswith(("$", "{", "process.env")):
                found[key] = val
    return found


def _harvest_firebase_config(session: TsurugiSession, base_url: str) -> Dict:
    """
    Fetch base_url + linked JS bundles, merge any Firebase config keys we find.
    Returns {"config": {...}, "sources": [urls where keys came from]}.
    """
    config: Dict[str, str] = {}
    sources: List[str] = []
    seen: Set[str] = set()

    log_info(f"Fetching {base_url}")
    resp = session.get(base_url, timeout=_BUNDLE_TIMEOUT)
    if resp is None:
        log_error("Could not fetch base URL")
        return {"config": config, "sources": sources}

    html = resp.text or ""
    inline_hits = _extract_config_from_text(html)
    if inline_hits:
        config.update(inline_hits)
        sources.append(base_url + " (inline)")

    # Harvest JS bundles.
    bundle_urls: List[str] = []
    for m in _SCRIPT_SRC.finditer(html):
        src = m.group(1)
        full = urljoin(base_url, src)
        if full in seen:
            continue
        seen.add(full)
        # Skip cross-origin CDN garbage (jquery, gtag, etc.) — Firebase config
        # almost always lives in same-origin app bundles.
        if urlparse(full).netloc not in (urlparse(base_url).netloc, ""):
            continue
        bundle_urls.append(full)

    bundle_urls = bundle_urls[:_MAX_BUNDLES]
    if bundle_urls:
        log_info(f"Scanning {len(bundle_urls)} same-origin JS bundle(s)")

    for url in bundle_urls:
        r = session.get(url, timeout=_BUNDLE_TIMEOUT)
        if r is None or r.status_code >= 400:
            continue
        body = r.text or ""
        hits = _extract_config_from_text(body)
        if not hits:
            continue
        # Merge — first hit per key wins (HTML > earliest bundle).
        for k, v in hits.items():
            if k not in config:
                config[k] = v
        sources.append(url)

    return {"config": config, "sources": sources}


# ─────────────────────────────────────────────────────────────────────────────
# Probes (each one is a self-contained oracle)
# ─────────────────────────────────────────────────────────────────────────────


def _derive_project_id(config: Dict[str, str]) -> Optional[str]:
    """projectId is the linchpin — derive from config or auth/database URLs."""
    if "projectId" in config:
        return config["projectId"]
    for key in ("databaseURL", "authDomain", "storageBucket"):
        v = config.get(key, "")
        # Patterns: <pid>.firebaseio.com, <pid>.firebaseapp.com,
        # <pid>.appspot.com, <pid>-default-rtdb.firebaseio.com
        m = re.match(r"^(?:https?://)?([a-z0-9-]+?)(?:-default-rtdb)?\.", v)
        if m:
            return m.group(1)
    return None


def _probe_rtdb(session: TsurugiSession, config: Dict[str, str]) -> Optional[Dict]:
    """
    Test Realtime Database read at /.json (root) — an open RTDB returns the
    full JSON tree or 'Permission denied' / 401.
    """
    db_url = config.get("databaseURL")
    if not db_url:
        pid = _derive_project_id(config)
        if not pid:
            return None
        # Default RTDB suffix changed in 2020; try the new shape first.
        db_url = f"https://{pid}-default-rtdb.firebaseio.com"

    db_url = db_url.rstrip("/")
    test_url = f"{db_url}/.json"
    r = session.get(test_url, timeout=10)
    if r is None:
        return None

    body = (r.text or "")[:500]
    if r.status_code == 200 and not body.lstrip().startswith('{"error"'):
        return {
            "type": "rtdb_open_read",
            "severity": "CRITICAL",
            "confidence": 0.95,
            "url": test_url,
            "evidence": body[:200],
            "oracle": "HTTP 200 + non-error JSON body at /.json",
            "impact": "Anonymous read of entire Realtime Database root.",
        }
    if r.status_code == 401 or '"error"' in body.lower():
        # Locked down — explicit "good" signal. Return None (not a finding).
        return None
    if r.status_code == 404:
        # Project URL guessed wrong, no RTDB enabled — also fine.
        return None
    # Anything else (403, 500…) — not a confident finding either way.
    return None


def _probe_firestore(session: TsurugiSession, config: Dict[str, str]) -> Optional[Dict]:
    """
    Test anonymous list against Firestore REST. We hit a tiny page (pageSize=1)
    on the default database, /documents (root collections list).
    """
    pid = _derive_project_id(config)
    if not pid:
        return None
    test_url = (
        f"https://firestore.googleapis.com/v1/projects/{pid}"
        f"/databases/(default)/documents?pageSize=1"
    )
    r = session.get(test_url, timeout=10)
    if r is None:
        return None

    body = (r.text or "")[:1000]
    # 200 with a JSON body that does NOT contain PERMISSION_DENIED is open.
    if r.status_code == 200:
        try:
            data = json.loads(body)
        except ValueError:
            return None
        if isinstance(data, dict) and "error" not in data:
            return {
                "type": "firestore_open_list",
                "severity": "CRITICAL",
                "confidence": 0.9,
                "url": test_url,
                "evidence": body[:200],
                "oracle": "HTTP 200 + valid JSON without PERMISSION_DENIED",
                "impact": (
                    "Firestore default database lists root collections without "
                    "authentication — likely overly-permissive security rules."
                ),
            }
    return None


def _probe_identitytoolkit(session: TsurugiSession, config: Dict[str, str]) -> Optional[Dict]:
    """
    Test if anonymous account creation is enabled via Identity Toolkit.
    We call accounts:createAuthUri with a junk continueUri — a project that
    accepts the call (even if we don't *use* the auth URI) leaks providers.

    Important: we do NOT call signUp (which would actually create an account).
    """
    api_key = config.get("apiKey")
    if not api_key:
        return None

    test_url = (
        "https://identitytoolkit.googleapis.com/v1/accounts:createAuthUri"
        f"?key={api_key}"
    )
    payload = {
        "identifier": "tsurugi-recon@example.invalid",
        "continueUri": "http://localhost",
    }
    try:
        r = session.post(test_url, json=payload, timeout=10)
    except Exception:
        return None
    if r is None:
        return None

    body = (r.text or "")[:1000]
    try:
        data = json.loads(body)
    except ValueError:
        return None

    if r.status_code == 200 and isinstance(data, dict) and "error" not in data:
        providers = data.get("allProviders") or data.get("signinMethods") or []
        return {
            "type": "identitytoolkit_apikey_usable",
            "severity": "MEDIUM",
            "confidence": 0.7,
            "url": test_url.split("?")[0],
            "evidence": f"providers={providers}, registered={data.get('registered')}",
            "oracle": "createAuthUri returned 200 without error",
            "impact": (
                "Firebase API key is usable from any origin. Combined with "
                "weak Firestore/RTDB rules, this enables full anonymous "
                "exploitation. By itself: information disclosure."
            ),
        }
    return None


def _probe_storage(session: TsurugiSession, config: Dict[str, str]) -> Optional[Dict]:
    """
    Test default Cloud Storage bucket for unauthenticated object listing
    via the Firebase Storage REST endpoint.
    """
    bucket = config.get("storageBucket")
    if not bucket:
        pid = _derive_project_id(config)
        if not pid:
            return None
        bucket = f"{pid}.appspot.com"

    test_url = f"https://firebasestorage.googleapis.com/v0/b/{bucket}/o?maxResults=1"
    r = session.get(test_url, timeout=10)
    if r is None:
        return None

    body = (r.text or "")[:500]
    try:
        data = json.loads(body)
    except ValueError:
        return None

    if r.status_code == 200 and isinstance(data, dict) and "error" not in data:
        return {
            "type": "storage_bucket_listable",
            "severity": "HIGH",
            "confidence": 0.85,
            "url": test_url,
            "evidence": body[:200],
            "oracle": "HTTP 200 + JSON object listing without error field",
            "impact": "Cloud Storage bucket lists objects without authentication.",
        }
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────


def run_firebase_scan(
    url: str,
    cookie: Optional[str] = None,
    proxy: Optional[str] = None,
) -> List[Dict]:
    """
    Full Firebase recon + misconfiguration scan against a target URL.
    """
    console.print(
        f"\n[bold magenta][*] FIREBASE SCANNER[/bold magenta] -> [yellow]{url}[/yellow]"
    )

    session = TsurugiSession(cookie_string=cookie, proxy=proxy)

    harvest = _harvest_firebase_config(session, url)
    config = harvest["config"]
    sources = harvest["sources"]

    if not config:
        log_warning("No Firebase config detected on this page or its bundles.")
        console.print(
            "[dim]Tip: try the SPA root, the login page, or pass a deeper URL.[/dim]"
        )
        return []

    # Tell the user what we found before probing.
    log_success(f"Firebase config detected ({len(config)} keys).")
    cfg_table = Table(title="firebaseConfig", border_style="cyan", show_header=False)
    cfg_table.add_column("key", style="bold")
    cfg_table.add_column("value")
    for k in _CONFIG_KEYS:
        if k in config:
            v = config[k]
            cfg_table.add_row(k, v if k != "apiKey" else v[:8] + "..." + v[-4:])
    console.print(cfg_table)

    pid = _derive_project_id(config)
    if pid:
        console.print(f"[cyan]projectId resolved: {pid}[/cyan]")
    else:
        log_warning("Could not derive projectId — some probes will be skipped.")

    # Run probes.
    probes = (
        ("RTDB anonymous read", _probe_rtdb),
        ("Firestore anonymous list", _probe_firestore),
        ("Identity Toolkit usability", _probe_identitytoolkit),
        ("Storage bucket listing", _probe_storage),
    )

    findings: List[Dict] = []
    for name, fn in probes:
        log_info(f"Probing: {name}")
        try:
            f = fn(session, config)
        except Exception as e:
            log_error(f"  Probe crashed ({name}): {e}")
            continue
        if f:
            findings.append(f)
            sev = f["severity"]
            color = {
                "CRITICAL": "bold red",
                "HIGH": "red",
                "MEDIUM": "yellow",
                "LOW": "dim",
            }.get(sev, "white")
            console.print(
                f"  [{color}][!] {sev}[/{color}] {f['type']}  "
                f"[dim](confidence {f['confidence']:.2f})[/dim]"
            )
        else:
            console.print(f"  [green][OK][/green] [dim]{name}: no issue[/dim]")

    # Output.
    if findings:
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        findings.sort(key=lambda x: severity_order.get(x["severity"], 4))

        body = "\n\n".join(
            f"[bold]{f['type']}[/bold]  ({f['severity']}, conf {f['confidence']:.2f})\n"
            f"  oracle: {f['oracle']}\n"
            f"  impact: {f['impact']}\n"
            f"  url: {f['url']}"
            for f in findings
        )
        console.print(
            Panel(body, title="[bold red][!] FIREBASE FINDINGS[/bold red]", border_style="red")
        )

        save_loot(
            "firebase",
            url,
            {
                "target": url,
                "project_id": pid,
                "config_keys": sorted(config.keys()),
                "config_sources": sources,
                "findings": findings,
                "total": len(findings),
                "critical": sum(1 for f in findings if f["severity"] == "CRITICAL"),
                "high": sum(1 for f in findings if f["severity"] == "HIGH"),
            },
        )
        log_success(f"Saved {len(findings)} finding(s) to loot/")
    else:
        log_success("No Firebase misconfigurations detected — rules look tight.")
        # Still save the recon (config + sources) so it's auditable.
        save_loot(
            "firebase",
            url,
            {
                "target": url,
                "project_id": pid,
                "config_keys": sorted(config.keys()),
                "config_sources": sources,
                "findings": [],
                "total": 0,
            },
        )

    return findings
