"""Data models for Tuteliq SDK."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


# =============================================================================
# Enums
# =============================================================================


class Severity(str, Enum):
    """Severity levels for detected content."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class GroomingRisk(str, Enum):
    """Grooming risk levels."""

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RiskLevel(str, Enum):
    """Overall risk levels."""

    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EmotionTrend(str, Enum):
    """Emotion trend direction."""

    IMPROVING = "improving"
    STABLE = "stable"
    WORSENING = "worsening"


class Audience(str, Enum):
    """Target audience for action plans."""

    CHILD = "child"
    PARENT = "parent"
    EDUCATOR = "educator"
    PLATFORM = "platform"


class MessageRole(str, Enum):
    """Message role in conversations."""

    ADULT = "adult"
    CHILD = "child"
    UNKNOWN = "unknown"


# =============================================================================
# Common Types
# =============================================================================


@dataclass
class AnalysisContext:
    """Context for content analysis."""

    language: Optional[str] = None
    age_group: Optional[str] = None
    relationship: Optional[str] = None
    platform: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary, excluding None values."""
        return {k: v for k, v in {
            "language": self.language,
            "age_group": self.age_group,
            "relationship": self.relationship,
            "platform": self.platform,
        }.items() if v is not None}


@dataclass
class Usage:
    """API usage statistics."""

    limit: int
    used: int
    remaining: int


# =============================================================================
# Bullying Detection
# =============================================================================


@dataclass
class DetectBullyingInput:
    """Input for bullying detection."""

    content: str
    context: Optional[AnalysisContext] = None
    external_id: Optional[str] = None
    metadata: Optional[dict[str, Any]] = None


@dataclass
class BullyingResult:
    """Result from bullying detection."""

    is_bullying: bool
    bullying_type: list[str]
    confidence: float
    severity: Severity
    rationale: str
    recommended_action: str
    risk_score: float
    credits_used: Optional[int] = None
    external_id: Optional[str] = None
    metadata: Optional[dict[str, Any]] = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "BullyingResult":
        """Create from API response dictionary."""
        return cls(
            is_bullying=data["is_bullying"],
            bullying_type=data["bullying_type"],
            confidence=data["confidence"],
            severity=Severity(data["severity"]),
            rationale=data["rationale"],
            recommended_action=data["recommended_action"],
            risk_score=data["risk_score"],
            credits_used=data.get("credits_used"),
            external_id=data.get("external_id"),
            metadata=data.get("metadata"),
        )


# =============================================================================
# Grooming Detection
# =============================================================================


@dataclass
class GroomingMessage:
    """A message in a conversation for grooming detection."""

    role: MessageRole
    content: str
    timestamp: Optional[str] = None


@dataclass
class DetectGroomingInput:
    """Input for grooming detection."""

    messages: list[GroomingMessage]
    child_age: Optional[int] = None
    context: Optional[AnalysisContext] = None
    external_id: Optional[str] = None
    metadata: Optional[dict[str, Any]] = None


@dataclass
class GroomingResult:
    """Result from grooming detection."""

    grooming_risk: GroomingRisk
    confidence: float
    flags: list[str]
    rationale: str
    risk_score: float
    recommended_action: str
    credits_used: Optional[int] = None
    external_id: Optional[str] = None
    metadata: Optional[dict[str, Any]] = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "GroomingResult":
        """Create from API response dictionary."""
        return cls(
            grooming_risk=GroomingRisk(data["grooming_risk"]),
            confidence=data["confidence"],
            flags=data["flags"],
            rationale=data["rationale"],
            risk_score=data["risk_score"],
            recommended_action=data["recommended_action"],
            credits_used=data.get("credits_used"),
            external_id=data.get("external_id"),
            metadata=data.get("metadata"),
        )


# =============================================================================
# Unsafe Content Detection
# =============================================================================


@dataclass
class DetectUnsafeInput:
    """Input for unsafe content detection."""

    content: str
    context: Optional[AnalysisContext] = None
    external_id: Optional[str] = None
    metadata: Optional[dict[str, Any]] = None


@dataclass
class UnsafeResult:
    """Result from unsafe content detection."""

    unsafe: bool
    categories: list[str]
    severity: Severity
    confidence: float
    risk_score: float
    rationale: str
    recommended_action: str
    credits_used: Optional[int] = None
    external_id: Optional[str] = None
    metadata: Optional[dict[str, Any]] = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "UnsafeResult":
        """Create from API response dictionary."""
        return cls(
            unsafe=data["unsafe"],
            categories=data["categories"],
            severity=Severity(data["severity"]),
            confidence=data["confidence"],
            risk_score=data["risk_score"],
            rationale=data["rationale"],
            recommended_action=data["recommended_action"],
            credits_used=data.get("credits_used"),
            external_id=data.get("external_id"),
            metadata=data.get("metadata"),
        )


# =============================================================================
# Quick Analysis
# =============================================================================


@dataclass
class AnalyzeInput:
    """Input for quick analysis."""

    content: str
    context: Optional[AnalysisContext] = None
    include: Optional[list[str]] = None  # ["bullying", "unsafe"]
    external_id: Optional[str] = None
    metadata: Optional[dict[str, Any]] = None


@dataclass
class AnalyzeResult:
    """Result from quick analysis."""

    risk_level: RiskLevel
    risk_score: float
    summary: str
    bullying: Optional[BullyingResult] = None
    unsafe: Optional[UnsafeResult] = None
    recommended_action: str = "none"
    credits_used: Optional[int] = None
    external_id: Optional[str] = None
    metadata: Optional[dict[str, Any]] = None


# =============================================================================
# Emotion Analysis
# =============================================================================


@dataclass
class EmotionMessage:
    """A message for emotion analysis."""

    sender: str
    content: str
    timestamp: Optional[str] = None


@dataclass
class AnalyzeEmotionsInput:
    """Input for emotion analysis."""

    content: Optional[str] = None
    messages: Optional[list[EmotionMessage]] = None
    context: Optional[AnalysisContext] = None
    external_id: Optional[str] = None
    metadata: Optional[dict[str, Any]] = None


@dataclass
class EmotionsResult:
    """Result from emotion analysis."""

    dominant_emotions: list[str]
    emotion_scores: dict[str, float]
    trend: EmotionTrend
    summary: str
    recommended_followup: str
    credits_used: Optional[int] = None
    external_id: Optional[str] = None
    metadata: Optional[dict[str, Any]] = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "EmotionsResult":
        """Create from API response dictionary."""
        return cls(
            dominant_emotions=data["dominant_emotions"],
            emotion_scores=data["emotion_scores"],
            trend=EmotionTrend(data["trend"]),
            summary=data["summary"],
            recommended_followup=data["recommended_followup"],
            credits_used=data.get("credits_used"),
            external_id=data.get("external_id"),
            metadata=data.get("metadata"),
        )


# =============================================================================
# Action Plan
# =============================================================================


@dataclass
class GetActionPlanInput:
    """Input for action plan generation."""

    situation: str
    child_age: Optional[int] = None
    audience: Optional[Audience] = None
    severity: Optional[Severity] = None
    external_id: Optional[str] = None
    metadata: Optional[dict[str, Any]] = None


@dataclass
class ActionPlanResult:
    """Result from action plan generation."""

    audience: str
    steps: list[str]
    tone: str
    reading_level: Optional[str] = None
    credits_used: Optional[int] = None
    external_id: Optional[str] = None
    metadata: Optional[dict[str, Any]] = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ActionPlanResult":
        """Create from API response dictionary."""
        return cls(
            audience=data["audience"],
            steps=data["steps"],
            tone=data["tone"],
            reading_level=data.get("approx_reading_level"),
            credits_used=data.get("credits_used"),
            external_id=data.get("external_id"),
            metadata=data.get("metadata"),
        )


# =============================================================================
# Incident Report
# =============================================================================


@dataclass
class ReportMessage:
    """A message for incident report."""

    sender: str
    content: str
    timestamp: Optional[str] = None


@dataclass
class GenerateReportInput:
    """Input for incident report generation."""

    messages: list[ReportMessage]
    child_age: Optional[int] = None
    incident_type: Optional[str] = None
    occurred_at: Optional[str] = None
    notes: Optional[str] = None
    external_id: Optional[str] = None
    metadata: Optional[dict[str, Any]] = None


@dataclass
class ReportResult:
    """Result from incident report generation."""

    summary: str
    risk_level: RiskLevel
    categories: list[str]
    recommended_next_steps: list[str]
    credits_used: Optional[int] = None
    external_id: Optional[str] = None
    metadata: Optional[dict[str, Any]] = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ReportResult":
        """Create from API response dictionary."""
        return cls(
            summary=data["summary"],
            risk_level=RiskLevel(data["risk_level"]),
            categories=data["categories"],
            recommended_next_steps=data["recommended_next_steps"],
            credits_used=data.get("credits_used"),
            external_id=data.get("external_id"),
            metadata=data.get("metadata"),
        )


# =============================================================================
# Account Management (GDPR)
# =============================================================================


@dataclass
class AccountDeletionResult:
    """Result from account data deletion (GDPR Article 17)."""

    message: str
    deleted_count: int

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AccountDeletionResult":
        """Create from API response dictionary."""
        return cls(
            message=data["message"],
            deleted_count=data["deleted_count"],
        )


@dataclass
class AccountExportResult:
    """Result from account data export (GDPR Article 20)."""

    user_id: str
    exported_at: str
    data: dict[str, Any]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AccountExportResult":
        """Create from API response dictionary."""
        return cls(
            user_id=data["userId"],
            exported_at=data["exportedAt"],
            data=data["data"],
        )


# =============================================================================
# Consent Management (GDPR Article 7)
# =============================================================================


class ConsentType(str, Enum):
    """Types of consent that can be recorded."""

    DATA_PROCESSING = "data_processing"
    ANALYTICS = "analytics"
    MARKETING = "marketing"
    THIRD_PARTY_SHARING = "third_party_sharing"
    CHILD_SAFETY_MONITORING = "child_safety_monitoring"


class ConsentStatus(str, Enum):
    """Consent status."""

    GRANTED = "granted"
    WITHDRAWN = "withdrawn"


@dataclass
class RecordConsentInput:
    """Input for recording consent."""

    consent_type: ConsentType
    version: str


@dataclass
class ConsentRecord:
    """A consent record."""

    id: str
    user_id: str
    consent_type: ConsentType
    status: ConsentStatus
    version: str
    created_at: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ConsentRecord":
        """Create from API response dictionary."""
        return cls(
            id=data["id"],
            user_id=data["user_id"],
            consent_type=ConsentType(data["consent_type"]),
            status=ConsentStatus(data["status"]),
            version=data["version"],
            created_at=data["created_at"],
        )


@dataclass
class ConsentActionResult:
    """Result from consent record/withdraw operations."""

    message: str
    consent: ConsentRecord

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ConsentActionResult":
        """Create from API response dictionary."""
        return cls(
            message=data["message"],
            consent=ConsentRecord.from_dict(data["consent"]),
        )


@dataclass
class ConsentStatusResult:
    """Result from consent status query."""

    consents: list[ConsentRecord]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ConsentStatusResult":
        """Create from API response dictionary."""
        return cls(
            consents=[ConsentRecord.from_dict(c) for c in data["consents"]],
        )


# =============================================================================
# Right to Rectification (GDPR Article 16)
# =============================================================================


@dataclass
class RectifyDataInput:
    """Input for data rectification."""

    collection: str
    document_id: str
    fields: dict[str, Any]


@dataclass
class RectifyDataResult:
    """Result from data rectification."""

    message: str
    updated_fields: list[str]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RectifyDataResult":
        """Create from API response dictionary."""
        return cls(
            message=data["message"],
            updated_fields=data["updated_fields"],
        )


# =============================================================================
# Audit Logs (GDPR Article 15)
# =============================================================================


class AuditAction(str, Enum):
    """Types of auditable actions."""

    DATA_ACCESS = "data_access"
    DATA_EXPORT = "data_export"
    DATA_DELETION = "data_deletion"
    DATA_RECTIFICATION = "data_rectification"
    CONSENT_GRANTED = "consent_granted"
    CONSENT_WITHDRAWN = "consent_withdrawn"
    BREACH_NOTIFICATION = "breach_notification"


@dataclass
class AuditLogEntry:
    """An audit log entry."""

    id: str
    user_id: str
    action: AuditAction
    created_at: str
    details: Optional[dict[str, Any]] = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AuditLogEntry":
        """Create from API response dictionary."""
        return cls(
            id=data["id"],
            user_id=data["user_id"],
            action=AuditAction(data["action"]),
            created_at=data["created_at"],
            details=data.get("details"),
        )


@dataclass
class AuditLogsResult:
    """Result from audit logs query."""

    audit_logs: list[AuditLogEntry]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AuditLogsResult":
        """Create from API response dictionary."""
        return cls(
            audit_logs=[AuditLogEntry.from_dict(l) for l in data["audit_logs"]],
        )


# =============================================================================
# Breach Management (GDPR Article 33/34)
# =============================================================================


class BreachSeverity(str, Enum):
    """Breach severity levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class BreachStatus(str, Enum):
    """Breach status values."""

    DETECTED = "detected"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    REPORTED = "reported"
    RESOLVED = "resolved"


class BreachNotificationStatus(str, Enum):
    """Breach notification status values."""

    PENDING = "pending"
    USERS_NOTIFIED = "users_notified"
    DPA_NOTIFIED = "dpa_notified"
    COMPLETED = "completed"


@dataclass
class LogBreachInput:
    """Input for logging a data breach."""

    title: str
    description: str
    severity: BreachSeverity
    affected_user_ids: list[str]
    data_categories: list[str]
    reported_by: str


@dataclass
class UpdateBreachInput:
    """Input for updating a breach."""

    status: BreachStatus
    notification_status: Optional[BreachNotificationStatus] = None
    notes: Optional[str] = None


@dataclass
class BreachRecord:
    """A breach record."""

    id: str
    title: str
    description: str
    severity: BreachSeverity
    status: BreachStatus
    notification_status: BreachNotificationStatus
    affected_user_ids: list[str]
    data_categories: list[str]
    reported_by: str
    notification_deadline: str
    created_at: str
    updated_at: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "BreachRecord":
        """Create from API response dictionary."""
        return cls(
            id=data["id"],
            title=data["title"],
            description=data["description"],
            severity=BreachSeverity(data["severity"]),
            status=BreachStatus(data["status"]),
            notification_status=BreachNotificationStatus(data["notification_status"]),
            affected_user_ids=data["affected_user_ids"],
            data_categories=data["data_categories"],
            reported_by=data["reported_by"],
            notification_deadline=data["notification_deadline"],
            created_at=data["created_at"],
            updated_at=data["updated_at"],
        )


@dataclass
class LogBreachResult:
    """Result from logging a breach."""

    message: str
    breach: BreachRecord

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "LogBreachResult":
        """Create from API response dictionary."""
        return cls(
            message=data["message"],
            breach=BreachRecord.from_dict(data["breach"]),
        )


@dataclass
class BreachListResult:
    """Result from listing breaches."""

    breaches: list[BreachRecord]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "BreachListResult":
        """Create from API response dictionary."""
        return cls(
            breaches=[BreachRecord.from_dict(b) for b in data["breaches"]],
        )


@dataclass
class BreachResult:
    """Result from getting/updating a breach."""

    breach: BreachRecord

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "BreachResult":
        """Create from API response dictionary."""
        return cls(
            breach=BreachRecord.from_dict(data["breach"]),
        )


# =============================================================================
# Voice Analysis
# =============================================================================


@dataclass
class TranscriptionSegment:
    """A segment of transcribed audio."""

    start: float
    end: float
    text: str


@dataclass
class TranscriptionResult:
    """Result from audio transcription."""

    text: str
    language: Optional[str] = None
    duration: Optional[float] = None
    segments: Optional[list[TranscriptionSegment]] = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TranscriptionResult":
        """Create from API response dictionary."""
        segments = None
        if "segments" in data and data["segments"]:
            segments = [
                TranscriptionSegment(s["start"], s["end"], s["text"])
                for s in data["segments"]
            ]
        return cls(
            text=data["text"],
            language=data.get("language"),
            duration=data.get("duration"),
            segments=segments,
        )


@dataclass
class VoiceAnalysisResult:
    """Result from voice/audio analysis."""

    file_id: Optional[str] = None
    transcription: Optional[TranscriptionResult] = None
    analysis: Optional[dict[str, Any]] = None
    overall_risk_score: Optional[float] = None
    overall_severity: Optional[str] = None
    credits_used: Optional[int] = None
    external_id: Optional[str] = None
    customer_id: Optional[str] = None
    metadata: Optional[dict[str, Any]] = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "VoiceAnalysisResult":
        """Create from API response dictionary."""
        transcription = None
        if "transcription" in data and data["transcription"]:
            transcription = TranscriptionResult.from_dict(data["transcription"])
        return cls(
            file_id=data.get("file_id"),
            transcription=transcription,
            analysis=data.get("analysis"),
            overall_risk_score=data.get("overall_risk_score"),
            overall_severity=data.get("overall_severity"),
            credits_used=data.get("credits_used"),
            external_id=data.get("external_id"),
            customer_id=data.get("customer_id"),
            metadata=data.get("metadata"),
        )


# =============================================================================
# Image Analysis
# =============================================================================


@dataclass
class VisionResult:
    """Result from visual analysis of an image."""

    extracted_text: Optional[str] = None
    visual_categories: Optional[list[str]] = None
    visual_severity: Optional[str] = None
    visual_confidence: Optional[float] = None
    visual_description: Optional[str] = None
    contains_text: Optional[bool] = None
    contains_faces: Optional[bool] = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "VisionResult":
        """Create from API response dictionary."""
        return cls(
            extracted_text=data.get("extracted_text"),
            visual_categories=data.get("visual_categories"),
            visual_severity=data.get("visual_severity"),
            visual_confidence=data.get("visual_confidence"),
            visual_description=data.get("visual_description"),
            contains_text=data.get("contains_text"),
            contains_faces=data.get("contains_faces"),
        )


@dataclass
class ImageAnalysisResult:
    """Result from image analysis."""

    file_id: Optional[str] = None
    vision: Optional[VisionResult] = None
    text_analysis: Optional[dict[str, Any]] = None
    overall_risk_score: Optional[float] = None
    overall_severity: Optional[str] = None
    credits_used: Optional[int] = None
    external_id: Optional[str] = None
    customer_id: Optional[str] = None
    metadata: Optional[dict[str, Any]] = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ImageAnalysisResult":
        """Create from API response dictionary."""
        vision = None
        if "vision" in data and data["vision"]:
            vision = VisionResult.from_dict(data["vision"])
        return cls(
            file_id=data.get("file_id"),
            vision=vision,
            text_analysis=data.get("text_analysis"),
            overall_risk_score=data.get("overall_risk_score"),
            overall_severity=data.get("overall_severity"),
            credits_used=data.get("credits_used"),
            external_id=data.get("external_id"),
            customer_id=data.get("customer_id"),
            metadata=data.get("metadata"),
        )


# =============================================================================
# Webhooks
# =============================================================================


@dataclass
class Webhook:
    """A webhook configuration."""

    id: str
    url: str
    events: list[str]
    active: bool
    secret: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Webhook":
        """Create from API response dictionary."""
        return cls(
            id=data["id"],
            url=data["url"],
            events=data["events"],
            active=data["active"],
            secret=data.get("secret"),
            created_at=data.get("created_at"),
            updated_at=data.get("updated_at"),
        )


@dataclass
class WebhookListResult:
    """Result from listing webhooks."""

    webhooks: list[Webhook]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "WebhookListResult":
        """Create from API response dictionary."""
        return cls(
            webhooks=[Webhook.from_dict(w) for w in data["webhooks"]],
        )


@dataclass
class CreateWebhookInput:
    """Input for creating a webhook."""

    url: str
    events: list[str]
    active: bool = True


@dataclass
class CreateWebhookResult:
    """Result from creating a webhook."""

    message: str
    webhook: Webhook

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CreateWebhookResult":
        """Create from API response dictionary."""
        return cls(
            message=data["message"],
            webhook=Webhook.from_dict(data["webhook"]),
        )


@dataclass
class UpdateWebhookInput:
    """Input for updating a webhook."""

    url: Optional[str] = None
    events: Optional[list[str]] = None
    active: Optional[bool] = None


@dataclass
class UpdateWebhookResult:
    """Result from updating a webhook."""

    message: str
    webhook: Webhook

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "UpdateWebhookResult":
        """Create from API response dictionary."""
        return cls(
            message=data["message"],
            webhook=Webhook.from_dict(data["webhook"]),
        )


@dataclass
class DeleteWebhookResult:
    """Result from deleting a webhook."""

    message: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "DeleteWebhookResult":
        """Create from API response dictionary."""
        return cls(message=data["message"])


@dataclass
class TestWebhookResult:
    """Result from testing a webhook."""

    message: str
    status_code: Optional[int] = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TestWebhookResult":
        """Create from API response dictionary."""
        return cls(
            message=data["message"],
            status_code=data.get("status_code"),
        )


@dataclass
class RegenerateSecretResult:
    """Result from regenerating a webhook secret."""

    message: str
    secret: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RegenerateSecretResult":
        """Create from API response dictionary."""
        return cls(
            message=data["message"],
            secret=data["secret"],
        )


# =============================================================================
# Pricing
# =============================================================================


@dataclass
class PricingPlan:
    """A pricing plan summary."""

    name: str
    price: str
    messages: str
    features: list[str]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PricingPlan":
        """Create from API response dictionary."""
        return cls(
            name=data["name"],
            price=data["price"],
            messages=data["messages"],
            features=data["features"],
        )


@dataclass
class PricingResult:
    """Result from pricing overview."""

    plans: list[PricingPlan]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PricingResult":
        """Create from API response dictionary."""
        return cls(
            plans=[PricingPlan.from_dict(p) for p in data["plans"]],
        )


@dataclass
class PricingDetailPlan:
    """A detailed pricing plan."""

    name: str
    tier: str
    price: dict[str, Any]
    limits: dict[str, Any]
    features: dict[str, Any]
    endpoints: list[str]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PricingDetailPlan":
        """Create from API response dictionary."""
        return cls(
            name=data["name"],
            tier=data["tier"],
            price=data["price"],
            limits=data["limits"],
            features=data["features"],
            endpoints=data["endpoints"],
        )


@dataclass
class PricingDetailsResult:
    """Result from detailed pricing query."""

    plans: list[PricingDetailPlan]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PricingDetailsResult":
        """Create from API response dictionary."""
        return cls(
            plans=[PricingDetailPlan.from_dict(p) for p in data["plans"]],
        )


# =============================================================================
# Usage
# =============================================================================


@dataclass
class UsageDay:
    """Usage data for a single day."""

    date: str
    total_requests: int
    success_requests: int
    error_requests: int

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "UsageDay":
        """Create from API response dictionary."""
        return cls(
            date=data["date"],
            total_requests=data["total_requests"],
            success_requests=data["success_requests"],
            error_requests=data["error_requests"],
        )


@dataclass
class UsageHistoryResult:
    """Result from usage history query."""

    api_key_id: str
    days: list[UsageDay]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "UsageHistoryResult":
        """Create from API response dictionary."""
        return cls(
            api_key_id=data["api_key_id"],
            days=[UsageDay.from_dict(d) for d in data["days"]],
        )


@dataclass
class UsageByToolResult:
    """Result from usage-by-tool query."""

    date: str
    tools: dict[str, int]
    endpoints: dict[str, int]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "UsageByToolResult":
        """Create from API response dictionary."""
        return cls(
            date=data["date"],
            tools=data["tools"],
            endpoints=data["endpoints"],
        )


@dataclass
class UsageMonthlyResult:
    """Result from monthly usage summary."""

    tier: str
    tier_display_name: str
    billing: dict[str, Any]
    usage: dict[str, Any]
    rate_limit: dict[str, Any]
    recommendations: Optional[dict[str, Any]]
    links: dict[str, Any]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "UsageMonthlyResult":
        """Create from API response dictionary."""
        return cls(
            tier=data["tier"],
            tier_display_name=data["tier_display_name"],
            billing=data["billing"],
            usage=data["usage"],
            rate_limit=data["rate_limit"],
            recommendations=data.get("recommendations"),
            links=data["links"],
        )
