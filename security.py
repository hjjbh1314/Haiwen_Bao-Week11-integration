"""
security.py - Security & Ethics Integration Module
Provides InputValidator, RateLimiter, and EthicalGuard for an AI agent system.
"""

import re
import time
import logging
from collections import defaultdict

# Configure logging for security events
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("security")


# ---------------------------------------------------------------------------
# 1. Input Validation & Sanitization
# ---------------------------------------------------------------------------
class InputValidator:
    """Validate and sanitise user input before it reaches the AI model."""

    # Patterns considered potentially dangerous (prompt injection, code injection)
    DANGEROUS_PATTERNS = [
        r"<script.*?>.*?</script>",       # XSS script tags
        r"javascript\s*:",                 # JS protocol
        r"(\b)(DROP|DELETE|INSERT|UPDATE)\s.*(TABLE|FROM|INTO)",  # SQL keywords
        r"\{\{.*?\}\}",                    # Template injection
        r"ignore\s+(all\s+)?(previous|above|prior)\s+(instructions|prompts)",  # Prompt injection
        r"(you\s+are|act\s+as|pretend\s+to\s+be)\s+(now\s+)?a\s+",            # Role hijacking
        r"system\s*:\s*",                  # Fake system prompt
    ]

    def __init__(self, max_length: int = 1000, min_length: int = 1):
        self.max_length = max_length
        self.min_length = min_length
        self._compiled = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in self.DANGEROUS_PATTERNS]

    def validate(self, input_text: str) -> tuple[bool, str]:
        """Return (is_valid, message) after checking length, format, and content."""
        # Type check
        if not isinstance(input_text, str):
            return False, "Input must be a string."

        # Length checks
        stripped = input_text.strip()
        if len(stripped) < self.min_length:
            return False, f"Input is too short (minimum {self.min_length} character(s))."
        if len(stripped) > self.max_length:
            return False, f"Input exceeds {self.max_length} characters."

        # Dangerous-pattern check
        for pattern in self._compiled:
            if pattern.search(stripped):
                return False, "Input contains potentially harmful content and was rejected."

        return True, "Valid"

    def sanitize(self, input_text: str) -> str:
        """Strip dangerous fragments and normalise whitespace."""
        text = input_text.strip()
        # Remove HTML tags
        text = re.sub(r"<[^>]*>", "", text)
        # Collapse whitespace
        text = re.sub(r"\s+", " ", text)
        return text


# ---------------------------------------------------------------------------
# 2. Rate Limiting
# ---------------------------------------------------------------------------
class RateLimiter:
    """Sliding-window rate limiter that tracks requests per user/session."""

    def __init__(self, max_requests: int = 10, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        # user_id -> list of request timestamps
        self._requests: dict[str, list[float]] = defaultdict(list)

    def _clean(self, user_id: str) -> None:
        """Remove timestamps outside the current window."""
        cutoff = time.time() - self.window_seconds
        self._requests[user_id] = [
            t for t in self._requests[user_id] if t > cutoff
        ]

    def allow_request(self, user_id: str = "default") -> tuple[bool, str]:
        """Check whether *user_id* may make another request right now."""
        self._clean(user_id)
        if len(self._requests[user_id]) >= self.max_requests:
            wait = self.window_seconds - (time.time() - self._requests[user_id][0])
            return False, (
                f"Rate limit exceeded. Max {self.max_requests} requests per "
                f"{self.window_seconds}s. Try again in {max(0, int(wait))}s."
            )
        self._requests[user_id].append(time.time())
        return True, "Request allowed."

    def remaining(self, user_id: str = "default") -> int:
        """Return how many requests the user can still make in this window."""
        self._clean(user_id)
        return max(0, self.max_requests - len(self._requests[user_id]))

    def reset(self, user_id: str = "default") -> None:
        """Manually reset the counter for a user."""
        self._requests.pop(user_id, None)


# ---------------------------------------------------------------------------
# 3. Ethical Guardrails
# ---------------------------------------------------------------------------
class EthicalGuard:
    """Content filter that blocks harmful or inappropriate requests."""

    # Category -> list of keyword / regex patterns
    DEFAULT_POLICIES = {
        "violence": [
            r"\b(kill|murder|attack|bomb|shoot|weapon)\b",
        ],
        "hate_speech": [
            r"\b(racial\s*slur|hate\s*speech|discriminat(e|ion))\b",
        ],
        "illegal_activity": [
            r"\b(hack(ing)?|exploit|steal|phishing|ransomware)\b",
        ],
        "self_harm": [
            r"\b(suicide|self[- ]?harm)\b",
        ],
    }

    def __init__(self, extra_policies: dict[str, list[str]] | None = None):
        policies = dict(self.DEFAULT_POLICIES)
        if extra_policies:
            for cat, patterns in extra_policies.items():
                policies.setdefault(cat, []).extend(patterns)
        self._compiled: dict[str, list[re.Pattern]] = {
            cat: [re.compile(p, re.IGNORECASE) for p in pats]
            for cat, pats in policies.items()
        }
        self.flagged_log: list[dict] = []  # in-memory audit log

    def check(self, text: str) -> tuple[bool, str]:
        """Return (is_safe, message). Logs any flagged content."""
        for category, patterns in self._compiled.items():
            for pat in patterns:
                if pat.search(text):
                    record = {
                        "timestamp": time.time(),
                        "category": category,
                        "pattern": pat.pattern,
                        "snippet": text[:120],
                    }
                    self.flagged_log.append(record)
                    logger.warning("Content flagged [%s]: %s", category, text[:80])
                    return False, (
                        f"Your request was flagged under policy '{category}'. "
                        "Please rephrase and try again."
                    )
        return True, "Content is acceptable."

    def check_output(self, text: str) -> tuple[bool, str]:
        """Screen model *output* for harmful content before returning to user."""
        for category, patterns in self._compiled.items():
            for pat in patterns:
                if pat.search(text):
                    record = {
                        "timestamp": time.time(),
                        "category": category,
                        "pattern": pat.pattern,
                        "snippet": text[:120],
                        "direction": "output",
                    }
                    self.flagged_log.append(record)
                    logger.warning("Output flagged [%s]: %s", category, text[:80])
                    return False, (
                        f"The model response was blocked under policy '{category}'. "
                        "The output contained potentially harmful content."
                    )
        return True, "Output is safe."

    def get_flagged_log(self) -> list[dict]:
        """Return the audit log of all flagged content."""
        return list(self.flagged_log)


# ---------------------------------------------------------------------------
# Convenience: run the full security pipeline in one call
# ---------------------------------------------------------------------------
def run_security_pipeline(
    text: str,
    user_id: str = "default",
    validator: InputValidator | None = None,
    limiter: RateLimiter | None = None,
    guard: EthicalGuard | None = None,
) -> tuple[bool, str, str]:
    """Run input validation -> rate-limit -> ethical check (BEFORE model).

    Returns (passed, message, sanitized_text).
    """
    validator = validator or InputValidator()
    limiter = limiter or RateLimiter()
    guard = guard or EthicalGuard()

    # Step 1 - validate input
    ok, msg = validator.validate(text)
    if not ok:
        return False, msg, ""

    # Step 2 - rate limit
    ok, msg = limiter.allow_request(user_id)
    if not ok:
        return False, msg, ""

    # Step 3 - ethical check on input
    sanitized = validator.sanitize(text)
    ok, msg = guard.check(sanitized)
    if not ok:
        return False, msg, ""

    return True, "All security checks passed.", sanitized


def check_model_output(
    output: str,
    guard: EthicalGuard | None = None,
) -> tuple[bool, str]:
    """Screen model output AFTER execution. Returns (is_safe, message)."""
    guard = guard or EthicalGuard()
    return guard.check_output(output)
