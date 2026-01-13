# HikariSystem Tsurugi/core/context.py
"""
TSURUGI CONTEXT - Dependency Injection Container
Encapsulates all session state for clean architecture.
"""
from dataclasses import dataclass, field
from typing import Optional, Dict, Any

@dataclass
class TsurugiContext:
    """
    Central context object passed to all modules.
    Replaces global state with explicit dependency injection.
    """
    # Authentication
    cookie: Optional[str] = None
    proxy: Optional[str] = None
    
    # TLS Fingerprint
    impersonate: str = "chrome120"
    
    # Stealth settings
    stealth_mode: bool = False
    min_delay: float = 0.5
    max_delay: float = 2.0
    
    # Cloudflare bypass
    cf_bypass: bool = False
    
    # OOB (Out-of-Band) client
    oob_client: Any = None
    
    # Headless browser mode
    headless: bool = False
    
    # Verbose output
    verbose: bool = False
    
    # Rate limiting
    requests_per_second: float = 10.0
    
    # Requester instance (lazy loaded)
    _requester: Any = field(default=None, repr=False)
    
    def get_requester(self):
        """Get or create the requester instance."""
        if self._requester is None:
            from core.requester import TsurugiSession
            self._requester = TsurugiSession(
                cookie_string=self.cookie,
                proxy=self.proxy,
                impersonate=self.impersonate,
                stealth=self.stealth_mode,
                cf_bypass=self.cf_bypass
            )
        return self._requester
    
    def clone(self, **overrides) -> 'TsurugiContext':
        """Create a copy with overridden values."""
        import dataclasses
        return dataclasses.replace(self, **overrides)
