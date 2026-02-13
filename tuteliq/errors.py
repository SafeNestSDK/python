"""Custom exceptions for Tuteliq SDK."""

from typing import Any, Optional


class TuteliqError(Exception):
    """Base exception for Tuteliq SDK errors."""

    def __init__(self, message: str, details: Optional[Any] = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details


class AuthenticationError(TuteliqError):
    """Raised when API key is invalid or missing."""

    pass


class RateLimitError(TuteliqError):
    """Raised when rate limit is exceeded."""

    pass


class ValidationError(TuteliqError):
    """Raised when request validation fails."""

    pass


class NotFoundError(TuteliqError):
    """Raised when a resource is not found."""

    pass


class ServerError(TuteliqError):
    """Raised when the server returns a 5xx error."""

    def __init__(
        self, message: str, status_code: int, details: Optional[Any] = None
    ) -> None:
        super().__init__(message, details)
        self.status_code = status_code


class TimeoutError(TuteliqError):
    """Raised when a request times out."""

    pass


class NetworkError(TuteliqError):
    """Raised when a network error occurs."""

    pass


class QuotaExceededError(TuteliqError):
    """Raised when monthly quota is exceeded."""

    pass


class TierAccessError(TuteliqError):
    """Raised when the endpoint requires a higher tier."""

    pass
