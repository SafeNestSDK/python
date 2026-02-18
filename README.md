<p align="center">
  <img src="./assets/logo.png" alt="Tuteliq" width="200" />
</p>

<h1 align="center">Tuteliq Python SDK</h1>

<p align="center">
  <strong>Official Python SDK for the Tuteliq API</strong><br>
  AI-powered child safety analysis
</p>

<p align="center">
  <a href="https://pypi.org/project/tuteliq/"><img src="https://img.shields.io/pypi/v/tuteliq.svg" alt="PyPI version"></a>
  <a href="https://pypi.org/project/tuteliq/"><img src="https://img.shields.io/pypi/pyversions/tuteliq.svg" alt="Python versions"></a>
  <a href="https://github.com/Tuteliq/python/actions"><img src="https://img.shields.io/github/actions/workflow/status/Tuteliq/python/ci.yml" alt="build status"></a>
  <a href="https://github.com/Tuteliq/python/blob/main/LICENSE"><img src="https://img.shields.io/github/license/Tuteliq/python.svg" alt="license"></a>
</p>

<p align="center">
  <a href="https://docs.tuteliq.ai">API Docs</a> •
  <a href="https://tuteliq.ai">Dashboard</a> •
  <a href="https://trust.tuteliq.ai">Trust</a> •
  <a href="https://discord.gg/7kbTeRYRXD">Discord</a>
</p>

---

## Installation

```bash
pip install tuteliq
```

### Requirements

- Python 3.9+

---

## Quick Start

```python
import asyncio
from tuteliq import Tuteliq

async def main():
    client = Tuteliq(api_key="your-api-key")

    # Quick safety analysis
    result = await client.analyze("Message to check")

    if result.risk_level != RiskLevel.SAFE:
        print(f"Risk: {result.risk_level}")
        print(f"Summary: {result.summary}")

    await client.close()

asyncio.run(main())
```

Or use as a context manager:

```python
async with Tuteliq(api_key="your-api-key") as client:
    result = await client.analyze("Message to check")
```

---

## API Reference

### Initialization

```python
from tuteliq import Tuteliq

# Simple
client = Tuteliq(api_key="your-api-key")

# With options
client = Tuteliq(
    api_key="your-api-key",
    timeout=30.0,      # Request timeout in seconds
    max_retries=3,     # Retry attempts
    retry_delay=1.0,   # Initial retry delay in seconds
)
```

### Bullying Detection

```python
result = await client.detect_bullying("Nobody likes you, just leave")

if result.is_bullying:
    print(f"Severity: {result.severity}")       # Severity.MEDIUM
    print(f"Types: {result.bullying_type}")     # ["exclusion", "verbal_abuse"]
    print(f"Confidence: {result.confidence}")   # 0.92
    print(f"Rationale: {result.rationale}")
```

### Grooming Detection

```python
from tuteliq import DetectGroomingInput, GroomingMessage, MessageRole

result = await client.detect_grooming(
    DetectGroomingInput(
        messages=[
            GroomingMessage(role=MessageRole.ADULT, content="This is our secret"),
            GroomingMessage(role=MessageRole.CHILD, content="Ok I won't tell"),
        ],
        child_age=12,
    )
)

if result.grooming_risk == GroomingRisk.HIGH:
    print(f"Flags: {result.flags}")  # ["secrecy", "isolation"]
```

### Unsafe Content Detection

```python
result = await client.detect_unsafe("I don't want to be here anymore")

if result.unsafe:
    print(f"Categories: {result.categories}")  # ["self_harm", "crisis"]
    print(f"Severity: {result.severity}")      # Severity.CRITICAL
```

### Quick Analysis

Runs bullying and unsafe detection in parallel:

```python
result = await client.analyze("Message to check")

print(f"Risk Level: {result.risk_level}")   # RiskLevel.SAFE/LOW/MEDIUM/HIGH/CRITICAL
print(f"Risk Score: {result.risk_score}")   # 0.0 - 1.0
print(f"Summary: {result.summary}")
print(f"Action: {result.recommended_action}")
```

### Emotion Analysis

```python
result = await client.analyze_emotions("I'm so stressed about everything")

print(f"Emotions: {result.dominant_emotions}")  # ["anxiety", "sadness"]
print(f"Trend: {result.trend}")                 # EmotionTrend.WORSENING
print(f"Followup: {result.recommended_followup}")
```

### Action Plan

```python
from tuteliq import GetActionPlanInput, Audience, Severity

plan = await client.get_action_plan(
    GetActionPlanInput(
        situation="Someone is spreading rumors about me",
        child_age=12,
        audience=Audience.CHILD,
        severity=Severity.MEDIUM,
    )
)

print(f"Steps: {plan.steps}")
print(f"Tone: {plan.tone}")
```

### Incident Report

```python
from tuteliq import GenerateReportInput, ReportMessage

report = await client.generate_report(
    GenerateReportInput(
        messages=[
            ReportMessage(sender="user1", content="Threatening message"),
            ReportMessage(sender="child", content="Please stop"),
        ],
        child_age=14,
    )
)

print(f"Summary: {report.summary}")
print(f"Risk: {report.risk_level}")
print(f"Next Steps: {report.recommended_next_steps}")
```

### Voice Streaming

Real-time voice streaming with live safety analysis over WebSocket. Requires `websockets`:

```bash
pip install tuteliq[voice]
```

```python
from tuteliq import VoiceStreamConfig, VoiceStreamHandlers

session = client.voice_stream(
    config=VoiceStreamConfig(
        interval_seconds=10,
        analysis_types=["bullying", "unsafe"],
    ),
    handlers=VoiceStreamHandlers(
        on_transcription=lambda e: print(f"Transcript: {e.text}"),
        on_alert=lambda e: print(f"Alert: {e.category} ({e.severity})"),
    ),
)

await session.connect()

# Send audio chunks as they arrive
await session.send_audio(audio_bytes)

# End session and get summary
summary = await session.end()
print(f"Risk: {summary.overall_risk}")
print(f"Score: {summary.overall_risk_score}")
print(f"Full transcript: {summary.transcript}")
```

---

## Credits Tracking

Each response includes the number of credits consumed:

```python
result = await client.detect_bullying("Test message")
print(f"Credits used: {result.credits_used}")  # 1
```

| Method | Credits | Notes |
|--------|---------|-------|
| `detect_bullying()` | 1 | Single text analysis |
| `detect_unsafe()` | 1 | Single text analysis |
| `detect_grooming()` | 1 per 10 msgs | `ceil(messages / 10)`, min 1 |
| `analyze_emotions()` | 1 per 10 msgs | `ceil(messages / 10)`, min 1 |
| `get_action_plan()` | 2 | Longer generation |
| `generate_report()` | 3 | Structured output |
| `analyze_voice()` | 5 | Transcription + analysis |
| `analyze_image()` | 3 | Vision + OCR + analysis |

---

## Tracking Fields

All methods support `external_id` and `metadata` for correlating requests:

```python
result = await client.detect_bullying(
    "Test message",
    external_id="msg_12345",
    metadata={"user_id": "usr_abc", "session": "sess_xyz"},
)

# Echoed back in response
print(result.external_id)  # "msg_12345"
print(result.metadata)     # {"user_id": "usr_abc", ...}
```

---

## Usage Tracking

```python
result = await client.detect_bullying("test")

# Access usage stats after any request
if client.usage:
    print(f"Limit: {client.usage.limit}")
    print(f"Used: {client.usage.used}")
    print(f"Remaining: {client.usage.remaining}")

# Request metadata
print(f"Request ID: {client.last_request_id}")
```

---

## Error Handling

```python
from tuteliq import (
    Tuteliq,
    TuteliqError,
    AuthenticationError,
    RateLimitError,
    ValidationError,
    NotFoundError,
    ServerError,
    TimeoutError,
    NetworkError,
)

try:
    result = await client.detect_bullying("test")
except AuthenticationError as e:
    print(f"Auth error: {e.message}")
except RateLimitError as e:
    print(f"Rate limited: {e.message}")
except ValidationError as e:
    print(f"Invalid input: {e.message}, details: {e.details}")
except ServerError as e:
    print(f"Server error {e.status_code}: {e.message}")
except TimeoutError as e:
    print(f"Timeout: {e.message}")
except NetworkError as e:
    print(f"Network error: {e.message}")
except TuteliqError as e:
    print(f"Error: {e.message}")
```

---

## Type Hints

The SDK is fully typed. All models are dataclasses with type hints:

```python
from tuteliq import (
    # Enums
    Severity,
    GroomingRisk,
    RiskLevel,
    EmotionTrend,
    Audience,
    MessageRole,
    # Input types
    AnalysisContext,
    DetectBullyingInput,
    DetectGroomingInput,
    DetectUnsafeInput,
    AnalyzeInput,
    AnalyzeEmotionsInput,
    GetActionPlanInput,
    GenerateReportInput,
    # Message types
    GroomingMessage,
    EmotionMessage,
    ReportMessage,
    # Result types
    BullyingResult,
    GroomingResult,
    UnsafeResult,
    AnalyzeResult,
    EmotionsResult,
    ActionPlanResult,
    ReportResult,
    Usage,
)
```

---

## FastAPI Example

```python
from fastapi import FastAPI, HTTPException
from tuteliq import Tuteliq, RateLimitError

app = FastAPI()
client = Tuteliq(api_key="your-api-key")

@app.post("/check-message")
async def check_message(message: str):
    try:
        result = await client.analyze(message)

        if result.risk_level.value in ["high", "critical"]:
            raise HTTPException(
                status_code=400,
                detail={"error": "Message blocked", "reason": result.summary}
            )

        return {"safe": True, "risk_level": result.risk_level.value}

    except RateLimitError:
        raise HTTPException(status_code=429, detail="Too many requests")
```

---

## Best Practices

### Message Batching

The **bullying** and **unsafe content** methods analyze a single `text` field per request. If your platform receives messages one at a time (e.g., a chat app), concatenate a **sliding window of recent messages** into one string before calling the API. Single words or short fragments lack context for accurate detection and can be exploited to bypass safety filters.

```python
# Bad — each message analyzed in isolation, easily evaded
for msg in messages:
    client.detect_bullying(text=msg)

# Good — recent messages analyzed together
window = " ".join(recent_messages[-10:])
client.detect_bullying(text=window)
```

The **grooming** method already accepts a `messages` list and analyzes the full conversation in context.

### PII Redaction

Enable `PII_REDACTION_ENABLED=true` on your Tuteliq API to automatically strip emails, phone numbers, URLs, social handles, IPs, and other PII from detection summaries and webhook payloads. The original text is still analyzed in full — only stored outputs are scrubbed.

---

## Support

- **API Docs**: [docs.tuteliq.ai](https://docs.tuteliq.ai)
- **Discord**: [discord.gg/7kbTeRYRXD](https://discord.gg/7kbTeRYRXD)
- **Email**: support@tuteliq.ai
- **Issues**: [GitHub Issues](https://github.com/Tuteliq/python/issues)

---

## License

MIT License - see [LICENSE](LICENSE) for details.

---

## Get Certified — Free

Tuteliq offers a **free certification program** for anyone who wants to deepen their understanding of online child safety. Complete a track, pass the quiz, and earn your official Tuteliq certificate — verified and shareable.

**Three tracks available:**

| Track | Who it's for | Duration |
|-------|-------------|----------|
| **Parents & Caregivers** | Parents, guardians, grandparents, teachers, coaches | ~90 min |
| **Young People (10–16)** | Young people who want to learn to spot manipulation | ~60 min |
| **Companies & Platforms** | Product managers, trust & safety teams, CTOs, compliance officers | ~120 min |

**Start here →** [tuteliq.ai/certify](https://tuteliq.ai/certify)

- 100% Free — no login required
- Verifiable certificate on completion
- Covers grooming recognition, sextortion, cyberbullying, regulatory obligations (KOSA, EU DSA), and more

---

## The Mission: Why This Matters

Before you decide to contribute or sponsor, read these numbers. They are not projections. They are not estimates from a pitch deck. They are verified statistics from the University of Edinburgh, UNICEF, NCMEC, and Interpol.

- **302 million** children are victims of online sexual exploitation and abuse every year. That is **10 children every second**. *(Childlight / University of Edinburgh, 2024)*
- **1 in 8** children globally have been victims of non-consensual sexual imagery in the past year. *(Childlight, 2024)*
- **370 million** girls and women alive today experienced rape or sexual assault in childhood. An estimated **240–310 million** boys and men experienced the same. *(UNICEF, 2024)*
- **29.2 million** incidents of suspected child sexual exploitation were reported to NCMEC's CyberTipline in 2024 alone — containing **62.9 million files** (images, videos). *(NCMEC, 2025)*
- **546,000** reports of online enticement (adults grooming children) in 2024 — a **192% increase** from the year before. *(NCMEC, 2025)*
- **1,325% increase** in AI-generated child sexual abuse material reports between 2023 and 2024. The technology that should protect children is being weaponized against them. *(NCMEC, 2025)*
- **100 sextortion reports per day** to NCMEC. Since 2021, at least **36 teenage boys** have taken their own lives because they were victimized by sextortion. *(NCMEC, 2025)*
- **84%** of reports resolve outside the United States. This is not an American problem. This is a **global emergency**. *(NCMEC, 2025)*

End-to-end encryption is making platforms blind. In 2024, platforms reported **7 million fewer incidents** than the year before — not because abuse stopped, but because they can no longer see it. The tools that catch known images are failing. The systems that rely on human moderators are overwhelmed. The technology to detect behavior — grooming patterns, escalation, manipulation — in real-time text conversations **exists right now**. It is running at [api.tuteliq.ai](https://api.tuteliq.ai).

The question is not whether this technology is possible. The question is whether we build the company to put it everywhere it needs to be.

**Every second we wait, another child is harmed.**

We have the technology. We need the support.

If this mission matters to you, consider [sponsoring our open-source work](https://github.com/sponsors/Tuteliq) so we can keep building the tools that protect children — and keep them free and accessible for everyone.

---

<p align="center">
  <sub>Built with care for child safety by the <a href="https://tuteliq.ai">Tuteliq</a> team</sub>
</p>
