# Mini-Assignment 6: Security & Ethics Integration

## System Overview

This project adds a simple security layer to an AI agent workflow. User input is checked before model execution, and model output is checked again before it is returned. The goal is to reduce abuse, unsafe requests, and harmful responses while keeping the workflow easy to test from Python scripts.

```
              ┌─── BEFORE model execution ───┐          ┌── AFTER ──┐
User Input  →  InputValidator → RateLimiter → EthicalGuard → Model → OutputFilter → User
              (validate+sanitize) (abuse control) (content check)      (screen response)
```

Main components:
- `InputValidator` checks type, length, and suspicious patterns, then sanitizes the text.
- `RateLimiter` tracks requests per user and enforces a time-window quota.
- `EthicalGuard` filters harmful content, logs flagged cases, and can also screen model output.

## Threat Model

| Threat | Description | Mitigation |
|---|---|---|
| **Prompt injection** | Input tries to override system behavior | Blocks phrases like "ignore previous instructions", fake `system:` prompts, and role hijacking |
| **Abuse / spam** | A user sends too many requests in a short time | Sliding-window rate limiting per user/session |
| **Harmful requests** | User asks for violence, hacking, hate, or self-harm content | EthicalGuard blocks unsafe content and returns feedback |
| **Code / script injection** | Input includes HTML, JavaScript, SQL, or template tricks | Validator rejects suspicious patterns and sanitizes text |

## Security Measures Implemented

### 1. Input Validation (InputValidator)

- Enforces configurable minimum and maximum input length.
- Rejects non-string input and suspicious patterns such as `<script>`, `javascript:`, SQL commands, `{{...}}`, and prompt injection phrases.
- Sanitizes accepted text by removing HTML tags and collapsing whitespace.

### 2. Rate Limiting (RateLimiter)

- Tracks request timestamps for each user.
- Enforces a configurable limit such as 10 requests per minute.
- Returns a clear error message and automatically resets after the time window expires.

### 3. Ethical Guardrails (EthicalGuard)

- Uses category-based rules for `violence`, `hate_speech`, `illegal_activity`, and `self_harm`.
- Logs flagged content with timestamp, category, matched pattern, and snippet.
- Gives user-friendly feedback asking the user to rephrase.

### 4. Output Filtering (check_model_output)

- Screens model responses after execution using the same policy categories.
- Prevents unsafe output from being returned even if the input passed earlier checks.
- Logs blocked output separately for review.

## How to Use

```bash
pip install python-dotenv pytest
python demo.py
python -m pytest test_security.py -v
```

```python
from security import run_security_pipeline, check_model_output

passed, message, clean_text = run_security_pipeline(
    text="Hello, explain quantum computing.",
    user_id="user_42",
)

if passed:
    response = call_model(clean_text)
    safe, out_msg = check_model_output(response)
    if safe:
        print(response)
    else:
        print(f"Output blocked: {out_msg}")
else:
    print(f"Input blocked: {message}")
```

## Limitations

- Filtering is regex-based, so advanced attacks and paraphrased harmful requests may still bypass it.
- Rate-limit state and audit logs are stored in memory, so they reset when the program restarts.
- The current rules are English-focused and may produce false positives or miss multilingual attacks.

## Future Improvements

- Add ML-based moderation alongside regex checks.
- Move rate limiting and logs to Redis or a database.
- Add stronger identity checks such as authenticated user IDs or IP-based controls.
