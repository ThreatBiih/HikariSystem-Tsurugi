# HikariSystem Tsurugi/core/diff_engine.py
"""
DIFFERENTIAL RESPONSE ANALYSIS ENGINE
Ultra-sensitive response comparison for blind vulnerability detection.

Compares:
- Response length (exact and fuzzy)
- Response time (timing attacks)
- HTTP headers differences
- Body content hash
- Specific patterns/keywords
"""
import time
import hashlib
import statistics
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from difflib import SequenceMatcher
from core.ui import console, log_info, log_warning

@dataclass
class ResponseFingerprint:
    """Fingerprint of an HTTP response for comparison."""
    status_code: int
    content_length: int
    response_time: float
    body_hash: str
    headers_hash: str
    word_count: int
    line_count: int
    has_error_keywords: bool
    body_sample: str  # First 500 chars for fuzzy comparison
    
    @classmethod
    def from_response(cls, response, response_time: float) -> 'ResponseFingerprint':
        """Create fingerprint from requests Response object."""
        body = response.text if hasattr(response, 'text') else str(response.content)
        
        # Error keywords that might indicate different behavior
        error_keywords = ['error', 'exception', 'invalid', 'denied', 'forbidden', 
                          'syntax', 'unexpected', 'failed', 'warning']
        has_errors = any(kw in body.lower() for kw in error_keywords)
        
        return cls(
            status_code=response.status_code,
            content_length=len(body),
            response_time=response_time,
            body_hash=hashlib.md5(body.encode()).hexdigest(),
            headers_hash=hashlib.md5(str(dict(response.headers)).encode()).hexdigest(),
            word_count=len(body.split()),
            line_count=body.count('\n'),
            has_error_keywords=has_errors,
            body_sample=body[:500]
        )

@dataclass 
class DiffResult:
    """Result of comparing two responses."""
    is_different: bool
    confidence: float  # 0.0 to 1.0
    differences: List[str]
    timing_anomaly: bool
    length_diff: int
    similarity_ratio: float
    
    def __str__(self):
        if not self.is_different:
            return "No significant differences detected"
        return f"DIFFERENT (confidence: {self.confidence:.1%}) - {', '.join(self.differences)}"

class DiffEngine:
    """
    Differential Response Analysis Engine.
    
    Usage:
        engine = DiffEngine()
        
        # Establish baseline
        engine.add_baseline(normal_response, response_time)
        
        # Compare payload response
        result = engine.compare(payload_response, response_time)
        if result.is_different:
            print("Potential vulnerability!")
    """
    
    def __init__(self, 
                 length_threshold: int = 50,
                 time_threshold: float = 1.0,
                 similarity_threshold: float = 0.95):
        """
        Args:
            length_threshold: Min length difference to flag (bytes)
            time_threshold: Min time difference to flag (seconds)
            similarity_threshold: Below this ratio = different (0.0-1.0)
        """
        self.baselines: List[ResponseFingerprint] = []
        self.length_threshold = length_threshold
        self.time_threshold = time_threshold
        self.similarity_threshold = similarity_threshold
        
        # For statistical analysis
        self.baseline_times: List[float] = []
        self.baseline_lengths: List[int] = []
    
    def add_baseline(self, response, response_time: float):
        """Add a baseline (normal) response for comparison."""
        fp = ResponseFingerprint.from_response(response, response_time)
        self.baselines.append(fp)
        self.baseline_times.append(response_time)
        self.baseline_lengths.append(fp.content_length)
    
    def get_baseline_stats(self) -> Dict:
        """Get statistical summary of baselines."""
        if not self.baselines:
            return {}
        
        return {
            "count": len(self.baselines),
            "avg_time": statistics.mean(self.baseline_times),
            "std_time": statistics.stdev(self.baseline_times) if len(self.baseline_times) > 1 else 0,
            "avg_length": statistics.mean(self.baseline_lengths),
            "std_length": statistics.stdev(self.baseline_lengths) if len(self.baseline_lengths) > 1 else 0,
        }
    
    def compare(self, response, response_time: float) -> DiffResult:
        """
        Compare a response against the baseline(s).
        
        Returns:
            DiffResult with analysis of differences
        """
        if not self.baselines:
            log_warning("No baselines set. Add baselines first.")
            return DiffResult(False, 0.0, ["No baseline"], False, 0, 1.0)
        
        fp = ResponseFingerprint.from_response(response, response_time)
        differences = []
        confidence_factors = []
        
        # Use the most recent baseline for comparison
        baseline = self.baselines[-1]
        stats = self.get_baseline_stats()
        
        # 1. Status Code Check (very significant)
        if fp.status_code != baseline.status_code:
            differences.append(f"Status: {baseline.status_code} -> {fp.status_code}")
            confidence_factors.append(0.9)
        
        # 2. Content Length Check (with statistical threshold)
        length_diff = abs(fp.content_length - baseline.content_length)
        if length_diff > self.length_threshold:
            # Use standard deviation if available
            if stats.get("std_length", 0) > 0:
                z_score = length_diff / stats["std_length"]
                if z_score > 2:  # More than 2 std deviations
                    differences.append(f"Length: {baseline.content_length} -> {fp.content_length} (Δ{length_diff})")
                    confidence_factors.append(min(0.8, z_score / 10))
            else:
                differences.append(f"Length: {baseline.content_length} -> {fp.content_length} (Δ{length_diff})")
                confidence_factors.append(0.5)
        
        # 3. Timing Analysis (for time-based attacks)
        timing_anomaly = False
        time_diff = response_time - stats.get("avg_time", response_time)
        if time_diff > self.time_threshold:
            timing_anomaly = True
            differences.append(f"Time: +{time_diff:.2f}s delay")
            confidence_factors.append(0.7)
        
        # 4. Body Hash (exact match check)
        if fp.body_hash != baseline.body_hash:
            # Different hash, now check similarity
            similarity = SequenceMatcher(None, baseline.body_sample, fp.body_sample).ratio()
            
            if similarity < self.similarity_threshold:
                differences.append(f"Body changed (similarity: {similarity:.1%})")
                confidence_factors.append(0.6)
        
        # 5. Error Keywords (new errors appearing)
        if fp.has_error_keywords and not baseline.has_error_keywords:
            differences.append("New error keywords detected")
            confidence_factors.append(0.75)
        
        # 6. Header Changes
        if fp.headers_hash != baseline.headers_hash:
            differences.append("Headers modified")
            confidence_factors.append(0.3)
        
        # 7. Word/Line Count Changes
        word_diff = abs(fp.word_count - baseline.word_count)
        if word_diff > 10:
            differences.append(f"Word count: {baseline.word_count} -> {fp.word_count}")
            confidence_factors.append(0.4)
        
        # Calculate overall confidence
        is_different = len(differences) > 0
        confidence = max(confidence_factors) if confidence_factors else 0.0
        
        # Boost confidence if multiple signals
        if len(confidence_factors) > 2:
            confidence = min(1.0, confidence + 0.1 * len(confidence_factors))
        
        similarity = SequenceMatcher(None, baseline.body_sample, fp.body_sample).ratio()
        
        return DiffResult(
            is_different=is_different,
            confidence=confidence,
            differences=differences,
            timing_anomaly=timing_anomaly,
            length_diff=length_diff,
            similarity_ratio=similarity
        )
    
    def detect_time_based(self, responses: List[Tuple], delay_threshold: float = 3.0) -> Tuple[bool, str]:
        """
        Detect time-based vulnerabilities by comparing response times.
        
        Args:
            responses: List of (payload, response, time) tuples
            delay_threshold: Minimum delay to consider significant
            
        Returns:
            (is_vulnerable, description)
        """
        if len(responses) < 2:
            return False, "Need at least 2 responses"
        
        # Separate into baseline (no delay) and test (with delay) requests
        times = [t for _, _, t in responses]
        avg_time = statistics.mean(times)
        
        # Find any response significantly slower
        for payload, resp, resp_time in responses:
            if resp_time > avg_time + delay_threshold:
                return True, f"Time-based detection: {payload} caused {resp_time:.2f}s delay (avg: {avg_time:.2f}s)"
        
        return False, "No timing anomalies detected"
    
    def reset(self):
        """Clear all baselines."""
        self.baselines.clear()
        self.baseline_times.clear()
        self.baseline_lengths.clear()


def quick_diff(baseline_response, test_response, baseline_time: float, test_time: float) -> DiffResult:
    """
    Quick one-shot comparison of two responses.
    
    Example:
        result = quick_diff(normal_resp, payload_resp, 0.5, 0.6)
        if result.is_different:
            print("Potential vuln!")
    """
    engine = DiffEngine()
    engine.add_baseline(baseline_response, baseline_time)
    return engine.compare(test_response, test_time)
