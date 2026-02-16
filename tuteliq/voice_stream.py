"""Voice streaming support for Tuteliq SDK."""

import asyncio
import json
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

VOICE_STREAM_URL = "wss://api.tuteliq.ai/voice/stream"


@dataclass
class VoiceStreamConfig:
    """Configuration for a voice streaming session."""

    interval_seconds: Optional[int] = None
    analysis_types: Optional[list[str]] = None
    context: Optional[dict[str, str]] = None


@dataclass
class VoiceReadyEvent:
    """Emitted when the session is ready."""

    session_id: str
    config: dict[str, Any]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "VoiceReadyEvent":
        return cls(session_id=data["session_id"], config=data["config"])


@dataclass
class VoiceTranscriptionSegment:
    """A segment of transcribed audio."""

    start: float
    end: float
    text: str


@dataclass
class VoiceTranscriptionEvent:
    """Emitted when a transcription flush arrives."""

    text: str
    segments: list[VoiceTranscriptionSegment]
    flush_index: int

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "VoiceTranscriptionEvent":
        segments = [
            VoiceTranscriptionSegment(s["start"], s["end"], s["text"])
            for s in data.get("segments", [])
        ]
        return cls(text=data["text"], segments=segments, flush_index=data["flush_index"])


@dataclass
class VoiceAlertEvent:
    """Emitted when a safety alert is triggered."""

    category: str
    severity: str
    risk_score: float
    details: dict[str, Any]
    flush_index: int

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "VoiceAlertEvent":
        return cls(
            category=data["category"],
            severity=data["severity"],
            risk_score=data["risk_score"],
            details=data.get("details", {}),
            flush_index=data["flush_index"],
        )


@dataclass
class VoiceSessionSummaryEvent:
    """Emitted when the session ends with a summary."""

    session_id: str
    duration_seconds: float
    overall_risk: str
    overall_risk_score: float
    total_flushes: int
    transcript: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "VoiceSessionSummaryEvent":
        return cls(
            session_id=data["session_id"],
            duration_seconds=data["duration_seconds"],
            overall_risk=data["overall_risk"],
            overall_risk_score=data["overall_risk_score"],
            total_flushes=data["total_flushes"],
            transcript=data["transcript"],
        )


@dataclass
class VoiceConfigUpdatedEvent:
    """Emitted when config is updated."""

    config: dict[str, Any]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "VoiceConfigUpdatedEvent":
        return cls(config=data["config"])


@dataclass
class VoiceErrorEvent:
    """Emitted on server-side errors."""

    code: str
    message: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "VoiceErrorEvent":
        return cls(code=data["code"], message=data["message"])


@dataclass
class VoiceStreamHandlers:
    """Callback handlers for voice stream events."""

    on_ready: Optional[Callable[[VoiceReadyEvent], None]] = None
    on_transcription: Optional[Callable[[VoiceTranscriptionEvent], None]] = None
    on_alert: Optional[Callable[[VoiceAlertEvent], None]] = None
    on_session_summary: Optional[Callable[[VoiceSessionSummaryEvent], None]] = None
    on_config_updated: Optional[Callable[[VoiceConfigUpdatedEvent], None]] = None
    on_error: Optional[Callable[[VoiceErrorEvent], None]] = None
    on_close: Optional[Callable[[int, str], None]] = None


class VoiceStreamSession:
    """A voice streaming session over WebSocket.

    Requires the ``websockets`` package::

        pip install websockets

    Example::

        session = client.voice_stream(
            config=VoiceStreamConfig(interval_seconds=10, analysis_types=["bullying", "unsafe"]),
            handlers=VoiceStreamHandlers(
                on_transcription=lambda e: print("Transcript:", e.text),
                on_alert=lambda e: print("Alert:", e.category, e.severity),
            ),
        )

        await session.connect()
        session.send_audio(audio_bytes)
        summary = await session.end()
        print("Risk:", summary.overall_risk)
    """

    def __init__(
        self,
        api_key: str,
        config: Optional[VoiceStreamConfig] = None,
        handlers: Optional[VoiceStreamHandlers] = None,
        base_url: Optional[str] = None,
    ) -> None:
        self._api_key = api_key
        self._config = config
        self._handlers = handlers or VoiceStreamHandlers()
        self._url = base_url or VOICE_STREAM_URL
        self._ws: Any = None
        self._session_id: Optional[str] = None
        self._active = False
        self._listener_task: Optional[asyncio.Task[None]] = None
        self._summary_future: Optional[asyncio.Future[VoiceSessionSummaryEvent]] = None

    @property
    def session_id(self) -> Optional[str]:
        """The session ID (available after ready event)."""
        return self._session_id

    @property
    def is_active(self) -> bool:
        """Whether the connection is active."""
        return self._active

    async def connect(self) -> None:
        """Open the WebSocket connection and wait for the ready event."""
        try:
            import websockets
        except ImportError:
            raise ImportError(
                'The "websockets" package is required for voice streaming. '
                "Install it with: pip install websockets"
            )

        self._ws = await websockets.connect(
            self._url,
            additional_headers={"Authorization": f"Bearer {self._api_key}"},
        )
        self._active = True

        if self._config:
            config_msg: dict[str, Any] = {"type": "config"}
            if self._config.interval_seconds is not None:
                config_msg["interval_seconds"] = self._config.interval_seconds
            if self._config.analysis_types is not None:
                config_msg["analysis_types"] = self._config.analysis_types
            if self._config.context is not None:
                config_msg["context"] = self._config.context
            await self._ws.send(json.dumps(config_msg))

        ready_future: asyncio.Future[None] = asyncio.get_event_loop().create_future()
        self._listener_task = asyncio.create_task(self._listen(ready_future))
        await ready_future

    async def _listen(self, ready_future: asyncio.Future[None]) -> None:
        """Background task that listens for server messages."""
        try:
            async for raw in self._ws:
                try:
                    data = json.loads(raw)
                except (json.JSONDecodeError, TypeError):
                    continue

                event_type = data.get("type")

                if event_type == "ready":
                    event = VoiceReadyEvent.from_dict(data)
                    self._session_id = event.session_id
                    if self._handlers.on_ready:
                        self._handlers.on_ready(event)
                    if not ready_future.done():
                        ready_future.set_result(None)

                elif event_type == "transcription":
                    if self._handlers.on_transcription:
                        self._handlers.on_transcription(
                            VoiceTranscriptionEvent.from_dict(data)
                        )

                elif event_type == "alert":
                    if self._handlers.on_alert:
                        self._handlers.on_alert(VoiceAlertEvent.from_dict(data))

                elif event_type == "session_summary":
                    event = VoiceSessionSummaryEvent.from_dict(data)
                    if self._handlers.on_session_summary:
                        self._handlers.on_session_summary(event)
                    if self._summary_future and not self._summary_future.done():
                        self._summary_future.set_result(event)

                elif event_type == "config_updated":
                    if self._handlers.on_config_updated:
                        self._handlers.on_config_updated(
                            VoiceConfigUpdatedEvent.from_dict(data)
                        )

                elif event_type == "error":
                    if self._handlers.on_error:
                        self._handlers.on_error(VoiceErrorEvent.from_dict(data))

        except Exception:
            pass
        finally:
            self._active = False
            if self._handlers.on_close:
                self._handlers.on_close(1000, "Connection closed")
            if self._summary_future and not self._summary_future.done():
                self._summary_future.set_exception(
                    ConnectionError("Connection closed before session summary")
                )
            if not ready_future.done():
                ready_future.set_exception(
                    ConnectionError("Connection closed before ready")
                )

    async def send_audio(self, data: bytes) -> None:
        """Send raw audio data (binary frame)."""
        if not self._ws or not self._active:
            raise ConnectionError("Voice stream is not connected")
        await self._ws.send(data)

    async def update_config(self, config: VoiceStreamConfig) -> None:
        """Update the session configuration."""
        if not self._ws or not self._active:
            raise ConnectionError("Voice stream is not connected")
        config_msg: dict[str, Any] = {"type": "config"}
        if config.interval_seconds is not None:
            config_msg["interval_seconds"] = config.interval_seconds
        if config.analysis_types is not None:
            config_msg["analysis_types"] = config.analysis_types
        if config.context is not None:
            config_msg["context"] = config.context
        await self._ws.send(json.dumps(config_msg))

    async def end(self) -> VoiceSessionSummaryEvent:
        """Signal end of audio. Returns the session summary."""
        if not self._ws or not self._active:
            raise ConnectionError("Voice stream is not connected")
        self._summary_future = asyncio.get_event_loop().create_future()
        await self._ws.send(json.dumps({"type": "end"}))
        return await self._summary_future

    async def close(self) -> None:
        """Force-close the connection immediately."""
        self._active = False
        if self._listener_task:
            self._listener_task.cancel()
        if self._ws:
            await self._ws.close()
            self._ws = None
