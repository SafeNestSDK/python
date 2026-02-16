"""
Tuteliq - AI-powered child safety API

Official Python SDK for detecting bullying, grooming, and unsafe content.

Example:
    >>> from tuteliq import Tuteliq
    >>> client = Tuteliq(api_key="your-api-key")
    >>> result = await client.detect_bullying("Some text to analyze")
    >>> print(result.is_bullying)
"""

from tuteliq.client import Tuteliq
from tuteliq.models import (
    # Enums
    Severity,
    GroomingRisk,
    RiskLevel,
    EmotionTrend,
    Audience,
    MessageRole,
    ConsentType,
    ConsentStatus,
    AuditAction,
    # Input types
    AnalysisContext,
    DetectBullyingInput,
    DetectGroomingInput,
    DetectUnsafeInput,
    AnalyzeInput,
    AnalyzeEmotionsInput,
    GetActionPlanInput,
    GenerateReportInput,
    GroomingMessage,
    EmotionMessage,
    ReportMessage,
    RecordConsentInput,
    RectifyDataInput,
    CreateWebhookInput,
    UpdateWebhookInput,
    # Result types
    BullyingResult,
    GroomingResult,
    UnsafeResult,
    AnalyzeResult,
    EmotionsResult,
    ActionPlanResult,
    ReportResult,
    Usage,
    # Voice/Image types
    TranscriptionSegment,
    TranscriptionResult,
    VoiceAnalysisResult,
    VisionResult,
    ImageAnalysisResult,
    # Webhook types
    Webhook,
    WebhookListResult,
    CreateWebhookResult,
    UpdateWebhookResult,
    DeleteWebhookResult,
    TestWebhookResult,
    RegenerateSecretResult,
    # Pricing types
    PricingPlan,
    PricingResult,
    PricingDetailPlan,
    PricingDetailsResult,
    # Usage types
    UsageDay,
    UsageHistoryResult,
    UsageByToolResult,
    UsageMonthlyResult,
    # Account types (GDPR)
    AccountDeletionResult,
    AccountExportResult,
    ConsentRecord,
    ConsentActionResult,
    ConsentStatusResult,
    RectifyDataResult,
    AuditLogEntry,
    AuditLogsResult,
)
from tuteliq.voice_stream import (
    VoiceStreamConfig,
    VoiceStreamHandlers,
    VoiceStreamSession,
    VoiceReadyEvent,
    VoiceTranscriptionEvent,
    VoiceTranscriptionSegment,
    VoiceAlertEvent,
    VoiceSessionSummaryEvent,
    VoiceConfigUpdatedEvent,
    VoiceErrorEvent,
)
from tuteliq.errors import (
    TuteliqError,
    AuthenticationError,
    RateLimitError,
    ValidationError,
    NotFoundError,
    ServerError,
    TimeoutError,
    NetworkError,
    QuotaExceededError,
    TierAccessError,
)

__version__ = "2.2.0"
__all__ = [
    # Client
    "Tuteliq",
    # Enums
    "Severity",
    "GroomingRisk",
    "RiskLevel",
    "EmotionTrend",
    "Audience",
    "MessageRole",
    "ConsentType",
    "ConsentStatus",
    "AuditAction",
    # Input types
    "AnalysisContext",
    "DetectBullyingInput",
    "DetectGroomingInput",
    "DetectUnsafeInput",
    "AnalyzeInput",
    "AnalyzeEmotionsInput",
    "GetActionPlanInput",
    "GenerateReportInput",
    "GroomingMessage",
    "EmotionMessage",
    "ReportMessage",
    "RecordConsentInput",
    "RectifyDataInput",
    "CreateWebhookInput",
    "UpdateWebhookInput",
    # Result types
    "BullyingResult",
    "GroomingResult",
    "UnsafeResult",
    "AnalyzeResult",
    "EmotionsResult",
    "ActionPlanResult",
    "ReportResult",
    "Usage",
    # Voice/Image types
    "TranscriptionSegment",
    "TranscriptionResult",
    "VoiceAnalysisResult",
    "VisionResult",
    "ImageAnalysisResult",
    # Webhook types
    "Webhook",
    "WebhookListResult",
    "CreateWebhookResult",
    "UpdateWebhookResult",
    "DeleteWebhookResult",
    "TestWebhookResult",
    "RegenerateSecretResult",
    # Pricing types
    "PricingPlan",
    "PricingResult",
    "PricingDetailPlan",
    "PricingDetailsResult",
    # Usage types
    "UsageDay",
    "UsageHistoryResult",
    "UsageByToolResult",
    "UsageMonthlyResult",
    # Account types (GDPR)
    "AccountDeletionResult",
    "AccountExportResult",
    "ConsentRecord",
    "ConsentActionResult",
    "ConsentStatusResult",
    "RectifyDataResult",
    "AuditLogEntry",
    "AuditLogsResult",
    # Voice streaming types
    "VoiceStreamConfig",
    "VoiceStreamHandlers",
    "VoiceStreamSession",
    "VoiceReadyEvent",
    "VoiceTranscriptionEvent",
    "VoiceTranscriptionSegment",
    "VoiceAlertEvent",
    "VoiceSessionSummaryEvent",
    "VoiceConfigUpdatedEvent",
    "VoiceErrorEvent",
    # Errors
    "TuteliqError",
    "AuthenticationError",
    "RateLimitError",
    "ValidationError",
    "NotFoundError",
    "ServerError",
    "TimeoutError",
    "NetworkError",
    "QuotaExceededError",
    "TierAccessError",
]
