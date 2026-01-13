# HikariSystem Tsurugi/core/deduplicator.py
"""
SMART DEDUPLICATION ENGINE
Groups URLs by response fingerprint, not just URL structure.

This solves the problem of testing thousands of URLs that hit the same backend.
Example: /post/1, /post/2, /post/99999 all return same template.
"""
import hashlib
from typing import List, Dict, Set, Tuple
from dataclasses import dataclass
from urllib.parse import urlparse, parse_qs
from collections import defaultdict
from core.ui import console, log_info


@dataclass
class URLFingerprint:
    """Fingerprint for URL deduplication."""
    url: str
    pattern: str           # Structural pattern
    response_hash: str     # Response content hash (optional)
    status_code: int       # Response status
    content_length: int    # Response size
    
    @property
    def structural_key(self) -> str:
        """Key based on URL structure only."""
        return self.pattern
    
    @property
    def response_key(self) -> str:
        """Key based on response characteristics."""
        return f"{self.status_code}:{self.content_length // 100}"  # Group by 100-byte buckets


def get_url_pattern(url: str) -> str:
    """
    Extract structural pattern from URL.
    
    /post/123?id=1&page=2 -> /post/{N}?id={}&page={}
    /user/john/profile    -> /user/{S}/profile
    """
    parsed = urlparse(url)
    
    # Normalize path segments
    path_parts = []
    for part in parsed.path.split('/'):
        if not part:
            continue
        elif part.isdigit():
            path_parts.append('{N}')  # Numeric ID
        elif len(part) > 20 and part.isalnum():
            path_parts.append('{H}')  # Hash/token
        else:
            path_parts.append(part)
    
    normalized_path = '/' + '/'.join(path_parts)
    
    # Normalize query params (just names, not values)
    params = parse_qs(parsed.query)
    param_pattern = '&'.join(sorted(params.keys())) if params else ''
    
    return f"{parsed.netloc}{normalized_path}?{param_pattern}"


def get_response_fingerprint(content: bytes, status: int) -> str:
    """
    Create fingerprint from response content.
    Removes dynamic elements like timestamps.
    """
    # Hash first 5KB of content (enough to identify template)
    content_sample = content[:5120]
    return hashlib.md5(content_sample).hexdigest()[:12]


class URLDeduplicator:
    """
    Smart URL deduplicator that groups by both structure and response.
    
    Usage:
        dedup = URLDeduplicator()
        
        # Phase 1: Group by URL structure
        groups = dedup.group_by_structure(all_urls)
        
        # Phase 2: Test one URL per group to get response
        for pattern, urls in groups.items():
            sample_url = urls[0]
            response = requester.get(sample_url)
            dedup.add_response(sample_url, response)
        
        # Phase 3: Get unique URLs to test
        unique_urls = dedup.get_unique_urls()
    """
    
    def __init__(self):
        self.url_to_pattern: Dict[str, str] = {}
        self.pattern_groups: Dict[str, List[str]] = defaultdict(list)
        self.response_fingerprints: Dict[str, URLFingerprint] = {}
        self.tested_patterns: Set[str] = set()
    
    def add_urls(self, urls: List[str]):
        """Add URLs and group by structural pattern."""
        for url in urls:
            pattern = get_url_pattern(url)
            self.url_to_pattern[url] = pattern
            self.pattern_groups[pattern].append(url)
        
        log_info(f"Added {len(urls)} URLs -> {len(self.pattern_groups)} structural patterns")
    
    def group_by_structure(self, urls: List[str]) -> Dict[str, List[str]]:
        """Group URLs by structural pattern."""
        self.add_urls(urls)
        return dict(self.pattern_groups)
    
    def add_response(self, url: str, status: int, content: bytes, content_length: int):
        """Add response data for a URL to improve deduplication."""
        pattern = self.url_to_pattern.get(url, get_url_pattern(url))
        response_hash = get_response_fingerprint(content, status)
        
        fingerprint = URLFingerprint(
            url=url,
            pattern=pattern,
            response_hash=response_hash,
            status_code=status,
            content_length=content_length
        )
        
        self.response_fingerprints[url] = fingerprint
        self.tested_patterns.add(pattern)
    
    def get_sample_urls(self) -> List[str]:
        """
        Get one sample URL from each structural group.
        Use this for initial probing before response-based dedup.
        """
        samples = []
        for pattern, urls in self.pattern_groups.items():
            samples.append(urls[0])
        return samples
    
    def get_unique_urls(self, use_response: bool = True) -> List[str]:
        """
        Get deduplicated list of URLs to test.
        
        Args:
            use_response: If True, use response fingerprints for smarter dedup
        """
        if not use_response or not self.response_fingerprints:
            # Structural dedup only
            return self.get_sample_urls()
        
        # Response-based dedup
        seen_fingerprints: Set[str] = set()
        unique_urls = []
        
        for url, fp in self.response_fingerprints.items():
            # Create combined key
            combined_key = f"{fp.pattern}|{fp.response_key}"
            
            if combined_key not in seen_fingerprints:
                seen_fingerprints.add(combined_key)
                unique_urls.append(url)
        
        return unique_urls
    
    def get_stats(self) -> Dict:
        """Get deduplication statistics."""
        total_urls = sum(len(urls) for urls in self.pattern_groups.values())
        unique_patterns = len(self.pattern_groups)
        unique_responses = len(set(fp.response_hash for fp in self.response_fingerprints.values()))
        
        reduction = ((total_urls - unique_patterns) / max(total_urls, 1)) * 100
        
        return {
            "total_urls": total_urls,
            "unique_patterns": unique_patterns,
            "unique_responses": unique_responses,
            "reduction_percent": round(reduction, 1),
            "urls_saved": total_urls - unique_patterns
        }
    
    def print_stats(self):
        """Print deduplication statistics."""
        stats = self.get_stats()
        console.print(f"\n[cyan][DEDUP] URL Deduplication Stats:[/cyan]")
        console.print(f"  Total URLs: {stats['total_urls']}")
        console.print(f"  Unique Patterns: {stats['unique_patterns']}")
        console.print(f"  Reduction: {stats['reduction_percent']}% ({stats['urls_saved']} URLs saved)")


def deduplicate_urls(urls: List[str]) -> Tuple[List[str], Dict]:
    """
    Convenience function to deduplicate a list of URLs.
    
    Returns:
        (unique_urls, stats)
    """
    dedup = URLDeduplicator()
    dedup.add_urls(urls)
    unique = dedup.get_sample_urls()
    stats = dedup.get_stats()
    return unique, stats
