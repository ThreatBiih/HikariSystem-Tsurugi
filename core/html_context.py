# HikariSystem Tsurugi/core/html_context.py
"""
HTML REFLECTION CONTEXT ANALYZER

Given an HTTP response body and a canary string, determines WHERE the canary
landed in the HTML parse tree and whether that context is exploitable for XSS.

Returns a list of ReflectionContext objects, one per occurrence, each carrying:
  - context_type: "html_text", "attr_value", "script", "comment", "url", "style"
  - escaped: whether the canary was HTML-entity-encoded at this location
  - exploitable: conservative boolean — can this context lead to JS exec?
  - confidence: 0.0–1.0 confidence that this specific reflection is a real vuln
  - breakout_hint: which payload shape would break out of this context
"""
import re
from dataclasses import dataclass
from enum import Enum
from typing import List


class ContextType(str, Enum):
    HTML_TEXT = "html_text"
    ATTR_UNQUOTED = "attr_unquoted"
    ATTR_SINGLE = "attr_single"
    ATTR_DOUBLE = "attr_double"
    ATTR_EVENT = "attr_event"
    ATTR_HREF = "attr_href"
    SCRIPT = "script"
    STYLE = "style"
    COMMENT = "comment"
    TAG_NAME = "tag_name"
    UNKNOWN = "unknown"


@dataclass
class ReflectionContext:
    context_type: ContextType
    escaped: bool
    exploitable: bool
    confidence: float
    breakout_hint: str
    position: int
    snippet: str


# Compiled once, reused forever.
_TAG_RE = re.compile(r"<[^>]*?>", re.DOTALL)
_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
_SCRIPT_RE = re.compile(r"<script[^>]*?>(.*?)</script>", re.DOTALL | re.IGNORECASE)
_STYLE_RE = re.compile(r"<style[^>]*?>(.*?)</style>", re.DOTALL | re.IGNORECASE)
_ATTR_RE = re.compile(
    r"""(\w[\w-]*)          # attr name
        \s*=\s*
        (?:
            "([^"]*?)"      # double-quoted
          | '([^']*?)'      # single-quoted
          | (\S+)           # unquoted
        )""",
    re.VERBOSE | re.DOTALL,
)
_EVENT_ATTRS = frozenset({
    "onabort", "onblur", "onchange", "onclick", "ondblclick", "onerror",
    "onfocus", "oninput", "onkeydown", "onkeypress", "onkeyup", "onload",
    "onmousedown", "onmousemove", "onmouseout", "onmouseover", "onmouseup",
    "onreset", "onresize", "onscroll", "onselect", "onsubmit", "onunload",
    "onanimationend", "onanimationstart", "ontoggle", "onpointerdown",
})
_HREF_ATTRS = frozenset({"href", "src", "action", "formaction", "data", "poster"})

# Entity patterns that indicate encoding of our canary.
_ENTITY_LT = re.compile(r"&lt;|&#0*60;|&#x0*3[cC];|\\u003[cC]")
_ENTITY_GT = re.compile(r"&gt;|&#0*62;|&#x0*3[eE];|\\u003[eE]")
_ENTITY_QUOTE_D = re.compile(r"&quot;|&#0*34;|&#x0*22;|\\u0022")
_ENTITY_QUOTE_S = re.compile(r"&#0*39;|&#x0*27;|\\u0027|&apos;")


def _is_encoded(haystack: str, canary: str) -> bool:
    """
    Returns True if the canary appears in the haystack ONLY in encoded form
    (i.e. surrounding < > ' " are entity-encoded).
    """
    # Quick check: if the raw canary is nowhere, bail.
    lower = haystack.lower()
    cl = canary.lower()
    if cl not in lower:
        return True  # not found at all ≈ fully encoded/removed

    # Search a 200-char window around each raw occurrence.
    idx = 0
    while True:
        pos = lower.find(cl, idx)
        if pos == -1:
            break
        window = haystack[max(0, pos - 60): pos + len(canary) + 60]
        # If < or > near the canary are entity-encoded, treat as escaped.
        if _ENTITY_LT.search(window) or _ENTITY_GT.search(window):
            idx = pos + 1
            continue
        # Found at least one raw (unencoded) occurrence.
        return False
    return True


def analyze_reflections(body: str, canary: str) -> List[ReflectionContext]:
    """
    Locate every occurrence of `canary` in `body` and classify its HTML context.
    """
    results: List[ReflectionContext] = []
    lower_body = body.lower()
    lower_canary = canary.lower()

    if lower_canary not in lower_body:
        return results

    # Build zone maps: intervals of special regions so we can classify
    # each canary position quickly.
    comment_zones = [(m.start(), m.end()) for m in _COMMENT_RE.finditer(body)]
    script_zones = [(m.start(1), m.end(1)) for m in _SCRIPT_RE.finditer(body)]
    style_zones = [(m.start(1), m.end(1)) for m in _STYLE_RE.finditer(body)]
    tag_zones = [(m.start(), m.end()) for m in _TAG_RE.finditer(body)]

    def _in_zone(pos: int, zones) -> bool:
        for s, e in zones:
            if s <= pos < e:
                return True
        return False

    idx = 0
    while True:
        pos = lower_body.find(lower_canary, idx)
        if pos == -1:
            break
        idx = pos + 1

        snippet = body[max(0, pos - 40): pos + len(canary) + 40]

        # --- Classify context ---

        # 1. Inside an HTML comment?
        if _in_zone(pos, comment_zones):
            results.append(ReflectionContext(
                context_type=ContextType.COMMENT,
                escaped=False,
                exploitable=True,
                confidence=0.25,
                breakout_hint="--><script>alert(1)</script><!--",
                position=pos,
                snippet=snippet,
            ))
            continue

        # 2. Inside a <script> block?
        if _in_zone(pos, script_zones):
            results.append(ReflectionContext(
                context_type=ContextType.SCRIPT,
                escaped=False,
                exploitable=True,
                confidence=0.8,
                breakout_hint="</script><script>alert(1)</script>",
                position=pos,
                snippet=snippet,
            ))
            continue

        # 3. Inside a <style> block?
        if _in_zone(pos, style_zones):
            results.append(ReflectionContext(
                context_type=ContextType.STYLE,
                escaped=False,
                exploitable=False,
                confidence=0.1,
                breakout_hint="</style><script>alert(1)</script>",
                position=pos,
                snippet=snippet,
            ))
            continue

        # 4. Inside an HTML tag (attribute)?
        if _in_zone(pos, tag_zones):
            # Find which tag we're in.
            for ts, te in tag_zones:
                if ts <= pos < te:
                    tag_text = body[ts:te]
                    break
            else:
                tag_text = ""

            # Try to find which attribute contains the canary.
            found_attr = False
            for m in _ATTR_RE.finditer(tag_text):
                attr_name = m.group(1).lower()
                val = m.group(2) or m.group(3) or m.group(4) or ""
                if lower_canary in val.lower():
                    found_attr = True
                    encoded = _is_encoded(val, canary)

                    if attr_name in _EVENT_ATTRS:
                        results.append(ReflectionContext(
                            context_type=ContextType.ATTR_EVENT,
                            escaped=encoded,
                            exploitable=not encoded,
                            confidence=0.85 if not encoded else 0.15,
                            breakout_hint=f'{attr_name}=alert(1)',
                            position=pos,
                            snippet=snippet,
                        ))
                    elif attr_name in _HREF_ATTRS:
                        results.append(ReflectionContext(
                            context_type=ContextType.ATTR_HREF,
                            escaped=encoded,
                            exploitable=not encoded,
                            confidence=0.7 if not encoded else 0.1,
                            breakout_hint="javascript:alert(1)",
                            position=pos,
                            snippet=snippet,
                        ))
                    elif m.group(2) is not None:
                        results.append(ReflectionContext(
                            context_type=ContextType.ATTR_DOUBLE,
                            escaped=encoded,
                            exploitable=not encoded and not _ENTITY_QUOTE_D.search(val),
                            confidence=0.5 if not encoded else 0.1,
                            breakout_hint='" onmouseover="alert(1)" x="',
                            position=pos,
                            snippet=snippet,
                        ))
                    elif m.group(3) is not None:
                        results.append(ReflectionContext(
                            context_type=ContextType.ATTR_SINGLE,
                            escaped=encoded,
                            exploitable=not encoded and not _ENTITY_QUOTE_S.search(val),
                            confidence=0.5 if not encoded else 0.1,
                            breakout_hint="' onmouseover='alert(1)' x='",
                            position=pos,
                            snippet=snippet,
                        ))
                    else:
                        results.append(ReflectionContext(
                            context_type=ContextType.ATTR_UNQUOTED,
                            escaped=encoded,
                            exploitable=not encoded,
                            confidence=0.65 if not encoded else 0.1,
                            breakout_hint="x onmouseover=alert(1)",
                            position=pos,
                            snippet=snippet,
                        ))
                    break

            if not found_attr:
                # Canary is in the tag but not in a recognized attribute value —
                # could be in tag name or malformed markup.
                results.append(ReflectionContext(
                    context_type=ContextType.TAG_NAME,
                    escaped=False,
                    exploitable=True,
                    confidence=0.4,
                    breakout_hint="><script>alert(1)</script>",
                    position=pos,
                    snippet=snippet,
                ))
            continue

        # 5. Plain HTML text node.
        encoded = _is_encoded(body[max(0, pos - 60): pos + len(canary) + 60], canary)
        results.append(ReflectionContext(
            context_type=ContextType.HTML_TEXT,
            escaped=encoded,
            exploitable=not encoded,
            confidence=0.6 if not encoded else 0.05,
            breakout_hint="<script>alert(1)</script>",
            position=pos,
            snippet=snippet,
        ))

    return results


def best_reflection(reflections: List[ReflectionContext]) -> ReflectionContext | None:
    """Return the highest-confidence exploitable reflection, or None."""
    exploitable = [r for r in reflections if r.exploitable]
    if not exploitable:
        return None
    return max(exploitable, key=lambda r: r.confidence)
