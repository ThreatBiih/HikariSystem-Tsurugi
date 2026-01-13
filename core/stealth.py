# HikariSystem Tsurugi/core/stealth.py
"""
STEALTH MODULE - Evasion and OPSEC utilities for Tsurugi
Provides header rotation, timing randomization, and fingerprint masking.
"""
import random
import time
from typing import Dict, List, Optional, Tuple

# Updated User-Agent pool (2024 versions, mobile + desktop)
USER_AGENTS = {
    "chrome_win": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    ],
    "chrome_mac": [
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    ],
    "firefox_win": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
    ],
    "firefox_linux": [
        "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
    ],
    "safari_mac": [
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    ],
    "edge_win": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    ],
    "mobile_android": [
        "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36",
    ],
    "mobile_ios": [
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    ],
}

# Accept headers matching UA families
ACCEPT_HEADERS = {
    "default": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
    "chrome": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "firefox": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
}

ACCEPT_LANGUAGES = [
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9,en-US;q=0.8",
    "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7",
    "es-ES,es;q=0.9,en;q=0.8",
    "de-DE,de;q=0.9,en;q=0.8",
    "fr-FR,fr;q=0.9,en;q=0.8",
]

ACCEPT_ENCODINGS = [
    "gzip, deflate, br",
    "gzip, deflate",
    "gzip, deflate, br, zstd",
]

# Common referer patterns
REFERERS = [
    "https://www.google.com/",
    "https://www.bing.com/",
    "https://duckduckgo.com/",
    "",  # Direct access
]


class StealthConfig:
    """Configuration for stealth mode."""
    
    def __init__(
        self,
        enabled: bool = False,
        min_delay: float = 0.5,
        max_delay: float = 2.0,
        rotate_ua: bool = True,
        rotate_headers: bool = True,
        use_referer: bool = True,
        ua_family: Optional[str] = None  # None = random, or "chrome", "firefox", "mobile"
    ):
        self.enabled = enabled
        self.min_delay = min_delay
        self.max_delay = max_delay
        self.rotate_ua = rotate_ua
        self.rotate_headers = rotate_headers
        self.use_referer = use_referer
        self.ua_family = ua_family
        
        # State tracking
        self._last_request_time = 0
        self._current_ua = None
        self._request_count = 0


class StealthEngine:
    """Engine for generating stealth headers and managing timing."""
    
    def __init__(self, config: StealthConfig = None):
        self.config = config or StealthConfig()
        self._ua_pool = self._build_ua_pool()
    
    def _build_ua_pool(self) -> List[str]:
        """Build User-Agent pool based on config."""
        if self.config.ua_family:
            # Filter by family
            family = self.config.ua_family.lower()
            pool = []
            for key, agents in USER_AGENTS.items():
                if family in key:
                    pool.extend(agents)
            return pool if pool else self._get_all_uas()
        return self._get_all_uas()
    
    def _get_all_uas(self) -> List[str]:
        """Get all User-Agents from pool."""
        all_uas = []
        for agents in USER_AGENTS.values():
            all_uas.extend(agents)
        return all_uas
    
    def get_random_ua(self) -> str:
        """Get random User-Agent from pool."""
        return random.choice(self._ua_pool)
    
    def get_stealth_headers(self, base_url: str = None) -> Dict[str, str]:
        """Generate stealth headers for request."""
        if not self.config.enabled:
            return {"User-Agent": self.get_random_ua()}
        
        ua = self.get_random_ua() if self.config.rotate_ua else self._ua_pool[0]
        
        # Determine browser family from UA
        is_firefox = "Firefox" in ua
        is_chrome = "Chrome" in ua and "Edg" not in ua
        
        headers = {
            "User-Agent": ua,
            "Accept": ACCEPT_HEADERS.get("firefox" if is_firefox else "chrome", ACCEPT_HEADERS["default"]),
            "Accept-Language": random.choice(ACCEPT_LANGUAGES),
            "Accept-Encoding": random.choice(ACCEPT_ENCODINGS),
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }
        
        if self.config.rotate_headers:
            # Add Cache-Control randomly
            if random.random() > 0.5:
                headers["Cache-Control"] = random.choice(["no-cache", "max-age=0"])
            
            # Add Pragma randomly
            if random.random() > 0.7:
                headers["Pragma"] = "no-cache"
        
        if self.config.use_referer and random.random() > 0.3:
            referer = random.choice(REFERERS)
            if referer:
                headers["Referer"] = referer
        
        # Add sec-fetch headers (modern browsers)
        if is_chrome or "Edg" in ua:
            headers["Sec-Fetch-Site"] = random.choice(["none", "same-origin", "cross-site"])
            headers["Sec-Fetch-Mode"] = "navigate"
            headers["Sec-Fetch-User"] = "?1"
            headers["Sec-Fetch-Dest"] = "document"
            headers["Sec-CH-UA-Platform"] = '"Windows"' if "Windows" in ua else '"macOS"'
        
        return headers
    
    def apply_delay(self) -> float:
        """Apply random delay between requests. Returns actual delay used."""
        if not self.config.enabled:
            return 0
        
        delay = random.uniform(self.config.min_delay, self.config.max_delay)
        time.sleep(delay)
        return delay
    
    def should_rotate_ua(self) -> bool:
        """Determine if UA should be rotated (every N requests)."""
        if not self.config.enabled:
            return False
        # Rotate UA every 5-15 requests
        return random.randint(1, 10) == 1


def detect_cloudflare(response_headers: Dict, response_text: str = "") -> Tuple[bool, str]:
    """
    Detect if response indicates Cloudflare protection.
    
    Returns:
        Tuple of (is_cloudflare, detection_type)
    """
    # Header-based detection
    cf_headers = ["cf-ray", "cf-cache-status", "cf-request-id", "__cfduid"]
    for header in cf_headers:
        if header.lower() in [h.lower() for h in response_headers.keys()]:
            # Cloudflare CDN detected, but may not be blocking
            if "server" in [h.lower() for h in response_headers.keys()]:
                server = response_headers.get("server", response_headers.get("Server", ""))
                if "cloudflare" in server.lower():
                    pass  # Confirmed CF
    
    # Check for challenge page indicators
    challenge_indicators = [
        "Checking your browser",
        "Please Wait... | Cloudflare",
        "Just a moment...",
        "_cf_chl_opt",
        "cf-spinner",
        "challenge-platform",
        "/cdn-cgi/challenge-platform/",
        "Attention Required! | Cloudflare",
        "ray ID:",
    ]
    
    for indicator in challenge_indicators:
        if indicator.lower() in response_text.lower():
            return True, "challenge_page"
    
    # Check cf-mitigated header (indicates bot was blocked)
    if response_headers.get("cf-mitigated") == "challenge":
        return True, "cf_mitigated"
    
    # Check for 403 with CF headers
    cf_ray = response_headers.get("cf-ray", response_headers.get("CF-RAY", ""))
    if cf_ray:
        return False, "cf_cdn_only"  # CF is present but not blocking
    
    return False, "none"


# Singleton for global stealth config
_global_stealth: Optional[StealthEngine] = None


def get_stealth_engine(config: StealthConfig = None) -> StealthEngine:
    """Get or create global stealth engine."""
    global _global_stealth
    if config:
        _global_stealth = StealthEngine(config)
    elif _global_stealth is None:
        _global_stealth = StealthEngine(StealthConfig())
    return _global_stealth


def enable_stealth(
    min_delay: float = 0.5,
    max_delay: float = 2.0,
    ua_family: str = None
) -> StealthEngine:
    """Enable stealth mode with given configuration."""
    config = StealthConfig(
        enabled=True,
        min_delay=min_delay,
        max_delay=max_delay,
        ua_family=ua_family
    )
    return get_stealth_engine(config)
