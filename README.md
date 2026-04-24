# Mini-Assignment 6: Security & Ethics Integration

## System Overview

This module provides a reusable security layer for AI agent systems. It sits between the user's raw input and the language model, ensuring every request is validated, rate-limited, and ethically screened before execution. The workflow is:

```
              ┌─── BEFORE model execution ───┐          ┌── AFTER ──┐
User Input  →  InputValidator → RateLimiter → EthicalGuard → Model → OutputFilter → User
              (validate+sanitize) (abuse control) (content check)      (screen response)
```

**Key components:**

- **`InputValidator`** — checks length, format, and sanitises dangerous content (XSS, SQL injection, template injection).
- **`RateLimiter`** — sliding-window limiter that tracks per-user request counts and rejects excess traffic.
- **`EthicalGuard`** — regex-based content filter that flags violence, hate speech, illegal activity, and self-harm, with an in-memory audit log.
- **`run_security_pipeline()`** — convenience function that chains all three checks in order (before model).
- **`check_model_output()`** — screens model responses after execution (after model).

## Threat Model

| Threat | Description | Mitigation |
|---|---|---|
| **Prompt Injection** | Attacker embeds instructions like "ignore previous instructions" to override model behaviour | InputValidator blocks `<script>`, `{{…}}`, SQL keywords, "ignore previous instructions", fake `system:` prompts, role hijacking |
| **Abuse / Spam** | Automated or manual flooding with excessive requests | RateLimiter enforces a per-user sliding-window cap (default 10 req/min) |
| **Harmful Content** | Users request violent, illegal, or self-harm-related output | EthicalGuard pattern-matches and blocks with user-friendly feedback |
| **XSS / Code Injection** | Malicious HTML or JavaScript injected into prompts | InputValidator strips tags and rejects `javascript:` URIs |
| **Data Exfiltration** | Template injection (`{{config.secrets}}`) to leak internal state | InputValidator rejects double-brace patterns |

## Security Measures Implemented

### 1. Input Validation (InputValidator)

- **Length limits** — configurable `min_length` / `max_length`; rejects empty or oversized input.
- **Dangerous-pattern detection** — compiled regex set catches `<script>`, SQL DDL/DML keywords, `javascript:` protocol, template injection, prompt injection ("ignore previous instructions"), fake system prompts, and role hijacking attempts.
- **Sanitisation** — `sanitize()` strips all HTML tags and collapses whitespace, producing clean text for the model.

### 2. Rate Limiting (RateLimiter)

- **Sliding window** — maintains a per-user list of timestamps; only counts requests within the active window.
- **Configurable** — `max_requests` and `window_seconds` can be tuned per deployment.
- **Remaining / Reset** — `remaining()` lets the UI show quota; `reset()` supports admin overrides.

### 3. Ethical Guardrails (EthicalGuard)

- **Category-based policies** — default categories: `violence`, `hate_speech`, `illegal_activity`, `self_harm`.
- **Extensible** — pass `extra_policies` to add custom categories (e.g., `spam`, `adult_content`).
- **Audit log** — every flagged request is recorded with timestamp, category, matched pattern, and a content snippet for review.
- **User feedback** — blocked requests receive a clear message naming the policy and inviting the user to rephrase.

### 4. Output Filtering (check_model_output)

- **Post-execution screening** — after the model generates a response, `check_model_output()` scans the output using the same ethical policies.
- **Prevents harmful output delivery** — even if a prompt passes input checks, the model's response is screened before reaching the user.
- **Audit trail** — flagged outputs are logged with `direction: "output"` to distinguish from input flags.

## How to Use

### Quick Start

```bash
pip install python-dotenv pytest
```

```python
from security import run_security_pipeline, check_model_output

# BEFORE model execution
passed, message, clean_text = run_security_pipeline(
    text="Hello, explain quantum computing.",
    user_id="user_42",
)

if passed:
    response = call_model(clean_text)

    # AFTER model execution
    safe, out_msg = check_model_output(response)
    if safe:
        print(response)       # deliver to user
    else:
        print(f"Output blocked: {out_msg}")
else:
    print(f"Input blocked: {message}")
```

### Running the Demo

```bash
python demo.py
```

### Running Tests

```bash
python -m pytest test_security.py -v
```

## Limitations

- **Regex-only filtering** — pattern matching cannot catch sophisticated prompt injection or novel phrasing. A production system should add ML-based classifiers.
- **In-memory state** — both the rate limiter and the audit log live in process memory. They reset on restart and do not work across multiple server instances. A production deployment would use Redis or a database.
- **English-centric** — keyword patterns target English text; multilingual evasion is not addressed.
- **No authentication** — `user_id` is caller-supplied. In production, it should come from a verified session/token.
- **False positives** — broad keywords (e.g., "attack" in a sports context) may incorrectly flag benign input. Tuning or allowlists would reduce this.

## Future Improvements

- Integrate an ML-based toxicity classifier (e.g., Perspective API) alongside regex filters.
- Move rate-limit state to Redis for distributed deployments.
- Add IP-based rate limiting in addition to user-ID tracking.
- Enhance output filtering with ML-based toxicity detection beyond regex matching.
- Support configurable severity levels (warn vs. block) per policy category.
