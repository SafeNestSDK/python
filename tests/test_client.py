"""Tests for Tuteliq client."""

import pytest
from tuteliq import (
    Tuteliq,
    Severity,
    GroomingRisk,
    RiskLevel,
    EmotionTrend,
    Audience,
    MessageRole,
    AnalysisContext,
    DetectBullyingInput,
    DetectGroomingInput,
    GroomingMessage,
    VerificationMode,
    DocumentType,
    VerificationStatus,
    VerificationSessionStatus,
    CreateVerificationSessionInput,
    VerificationSession,
    VerificationSessionResult,
    FaceMatchResult,
    LivenessResult,
    AgeVerificationResult,
    IdentityVerificationResult,
    VerificationRetrieveResult,
    IdentityRetrieveResult,
)


class TestClientInitialization:
    """Tests for client initialization."""

    def test_client_creation(self) -> None:
        """Test basic client creation."""
        client = Tuteliq(api_key="test-api-key-12345")
        assert client is not None

    def test_client_with_options(self) -> None:
        """Test client creation with options."""
        client = Tuteliq(
            api_key="test-api-key-12345",
            timeout=60.0,
            max_retries=5,
            retry_delay=2.0,
        )
        assert client is not None

    def test_client_requires_api_key(self) -> None:
        """Test that client requires API key."""
        with pytest.raises(ValueError, match="API key is required"):
            Tuteliq(api_key="")

    def test_client_validates_api_key_length(self) -> None:
        """Test that client validates API key length."""
        with pytest.raises(ValueError, match="appears to be invalid"):
            Tuteliq(api_key="short")


class TestEnums:
    """Tests for enum values."""

    def test_severity_values(self) -> None:
        """Test Severity enum values."""
        assert Severity.LOW.value == "low"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.HIGH.value == "high"
        assert Severity.CRITICAL.value == "critical"

    def test_grooming_risk_values(self) -> None:
        """Test GroomingRisk enum values."""
        assert GroomingRisk.NONE.value == "none"
        assert GroomingRisk.LOW.value == "low"
        assert GroomingRisk.HIGH.value == "high"
        assert GroomingRisk.CRITICAL.value == "critical"

    def test_risk_level_values(self) -> None:
        """Test RiskLevel enum values."""
        assert RiskLevel.SAFE.value == "safe"
        assert RiskLevel.LOW.value == "low"
        assert RiskLevel.CRITICAL.value == "critical"

    def test_emotion_trend_values(self) -> None:
        """Test EmotionTrend enum values."""
        assert EmotionTrend.IMPROVING.value == "improving"
        assert EmotionTrend.STABLE.value == "stable"
        assert EmotionTrend.WORSENING.value == "worsening"

    def test_audience_values(self) -> None:
        """Test Audience enum values."""
        assert Audience.CHILD.value == "child"
        assert Audience.PARENT.value == "parent"
        assert Audience.EDUCATOR.value == "educator"
        assert Audience.PLATFORM.value == "platform"

    def test_message_role_values(self) -> None:
        """Test MessageRole enum values."""
        assert MessageRole.ADULT.value == "adult"
        assert MessageRole.CHILD.value == "child"
        assert MessageRole.UNKNOWN.value == "unknown"


class TestModels:
    """Tests for data models."""

    def test_analysis_context(self) -> None:
        """Test AnalysisContext creation."""
        context = AnalysisContext(
            language="en",
            age_group="11-13",
            relationship="classmates",
            platform="chat",
        )
        assert context.language == "en"
        assert context.age_group == "11-13"

    def test_analysis_context_to_dict(self) -> None:
        """Test AnalysisContext.to_dict() excludes None values."""
        context = AnalysisContext(language="en")
        d = context.to_dict()
        assert d == {"language": "en"}
        assert "age_group" not in d

    def test_detect_bullying_input(self) -> None:
        """Test DetectBullyingInput creation."""
        input_data = DetectBullyingInput(
            content="Test message",
            external_id="msg_123",
            metadata={"user_id": "user_456"},
        )
        assert input_data.content == "Test message"
        assert input_data.external_id == "msg_123"

    def test_grooming_message(self) -> None:
        """Test GroomingMessage creation."""
        msg = GroomingMessage(
            role=MessageRole.ADULT,
            content="Hello",
        )
        assert msg.role == MessageRole.ADULT
        assert msg.content == "Hello"

    def test_detect_grooming_input(self) -> None:
        """Test DetectGroomingInput creation."""
        input_data = DetectGroomingInput(
            messages=[
                GroomingMessage(role=MessageRole.ADULT, content="Hello"),
                GroomingMessage(role=MessageRole.CHILD, content="Hi"),
            ],
            child_age=12,
        )
        assert len(input_data.messages) == 2
        assert input_data.child_age == 12


class TestVerificationEnums:
    """Tests for verification enum values."""

    def test_verification_mode_values(self) -> None:
        """Test VerificationMode enum values."""
        assert VerificationMode.AGE.value == "age"
        assert VerificationMode.IDENTITY.value == "identity"

    def test_document_type_values(self) -> None:
        """Test DocumentType enum values."""
        assert DocumentType.PASSPORT.value == "passport"
        assert DocumentType.ID_CARD.value == "id_card"
        assert DocumentType.DRIVERS_LICENSE.value == "drivers_license"

    def test_verification_status_values(self) -> None:
        """Test VerificationStatus enum values."""
        assert VerificationStatus.VERIFIED.value == "verified"
        assert VerificationStatus.FAILED.value == "failed"
        assert VerificationStatus.NEEDS_REVIEW.value == "needs_review"

    def test_verification_session_status_values(self) -> None:
        """Test VerificationSessionStatus enum values."""
        assert VerificationSessionStatus.PENDING.value == "pending"
        assert VerificationSessionStatus.IN_PROGRESS.value == "in_progress"
        assert VerificationSessionStatus.COMPLETED.value == "completed"
        assert VerificationSessionStatus.FAILED.value == "failed"
        assert VerificationSessionStatus.EXPIRED.value == "expired"
        assert VerificationSessionStatus.CANCELLED.value == "cancelled"


class TestVerificationModels:
    """Tests for verification data models."""

    def test_create_verification_session_input(self) -> None:
        """Test CreateVerificationSessionInput creation."""
        input_data = CreateVerificationSessionInput(
            mode=VerificationMode.AGE,
            document_type=DocumentType.PASSPORT,
            external_id="ext_123",
        )
        assert input_data.mode == VerificationMode.AGE
        assert input_data.document_type == DocumentType.PASSPORT
        assert input_data.external_id == "ext_123"

    def test_verification_session_from_dict(self) -> None:
        """Test VerificationSession.from_dict maps mobile_url to url."""
        data = {
            "session_id": "sess_abc",
            "mobile_url": "https://verify.tuteliq.ai/age/?session=abc&token=xyz",
            "expires_at": "2025-12-31T23:59:59Z",
            "mode": "age",
        }
        session = VerificationSession.from_dict(data)
        assert session.session_id == "sess_abc"
        assert session.url == "https://verify.tuteliq.ai/age/?session=abc&token=xyz"
        assert session.mode == VerificationMode.AGE

    def test_face_match_result_from_dict(self) -> None:
        """Test FaceMatchResult.from_dict."""
        data = {"matched": True, "distance": 0.3, "confidence": 0.95}
        result = FaceMatchResult.from_dict(data)
        assert result.matched is True
        assert result.distance == 0.3
        assert result.confidence == 0.95

    def test_liveness_result_from_dict(self) -> None:
        """Test LivenessResult.from_dict."""
        data = {"valid": True}
        result = LivenessResult.from_dict(data)
        assert result.valid is True
        assert result.reason is None

    def test_age_verification_result_from_dict(self) -> None:
        """Test AgeVerificationResult.from_dict."""
        data = {
            "verification_id": "vrf_123",
            "status": "verified",
            "age_bracket": "18-25",
            "is_minor": False,
            "face_match": {"matched": True, "distance": 0.2, "confidence": 0.98},
            "liveness": {"valid": True},
            "failure_reasons": [],
            "credits_used": 10,
        }
        result = AgeVerificationResult.from_dict(data)
        assert result.verification_id == "vrf_123"
        assert result.status == VerificationStatus.VERIFIED
        assert result.age_bracket == "18-25"
        assert result.is_minor is False
        assert result.face_match is not None
        assert result.face_match.matched is True
        assert result.liveness.valid is True
        assert result.credits_used == 10

    def test_identity_verification_result_from_dict(self) -> None:
        """Test IdentityVerificationResult.from_dict."""
        data = {
            "verification_id": "vrf_456",
            "status": "verified",
            "full_name": "John Doe",
            "date_of_birth": "1990-01-15",
            "document_type": "passport",
            "country_code": "GB",
            "face_match": {"matched": True, "distance": 0.15, "confidence": 0.99},
            "liveness": {"valid": True},
            "failure_reasons": [],
            "credits_used": 15,
        }
        result = IdentityVerificationResult.from_dict(data)
        assert result.verification_id == "vrf_456"
        assert result.status == VerificationStatus.VERIFIED
        assert result.full_name == "John Doe"
        assert result.country_code == "GB"
        assert result.credits_used == 15

    def test_verification_session_result_from_dict(self) -> None:
        """Test VerificationSessionResult.from_dict."""
        data = {
            "session_id": "sess_abc",
            "status": "completed",
            "mode": "age",
            "created_at": "2025-01-01T00:00:00Z",
            "expires_at": "2025-01-01T01:00:00Z",
            "age_result": {
                "verification_id": "vrf_123",
                "status": "verified",
                "is_minor": False,
                "face_match": None,
                "liveness": {"valid": True},
                "failure_reasons": [],
                "credits_used": 10,
            },
        }
        result = VerificationSessionResult.from_dict(data)
        assert result.session_id == "sess_abc"
        assert result.status == VerificationSessionStatus.COMPLETED
        assert result.mode == VerificationMode.AGE
        assert result.age_result is not None
        assert result.age_result.status == VerificationStatus.VERIFIED

    def test_verification_retrieve_result_from_dict(self) -> None:
        """Test VerificationRetrieveResult.from_dict."""
        data = {
            "verification_id": "vrf_789",
            "status": "verified",
            "age": 25,
            "is_minor": False,
            "face_matched": True,
            "face_confidence": 0.97,
            "liveness_valid": True,
            "failure_reasons": [],
            "created_at": "2025-01-01T00:00:00Z",
        }
        result = VerificationRetrieveResult.from_dict(data)
        assert result.verification_id == "vrf_789"
        assert result.status == VerificationStatus.VERIFIED
        assert result.age == 25
        assert result.is_minor is False

    def test_identity_retrieve_result_from_dict(self) -> None:
        """Test IdentityRetrieveResult.from_dict."""
        data = {
            "verification_id": "vrf_101",
            "status": "verified",
            "full_name": "Jane Doe",
            "date_of_birth": "1985-06-20",
            "document_type": "id_card",
            "country_code": "SE",
            "face_matched": True,
            "face_confidence": 0.96,
            "liveness_valid": True,
            "failure_reasons": [],
            "created_at": "2025-01-01T00:00:00Z",
        }
        result = IdentityRetrieveResult.from_dict(data)
        assert result.verification_id == "vrf_101"
        assert result.full_name == "Jane Doe"
        assert result.country_code == "SE"
