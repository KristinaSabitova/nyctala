"""ECS-lite event model.

Fields use dotted ECS names (``process.command_line``) as aliases; Python code
uses the snake_case attribute names. ``model_dump(by_alias=True)`` gives the
storage layout.
"""

import ipaddress
import uuid
from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from pydantic import AfterValidator, AwareDatetime, BaseModel, ConfigDict, Field, model_validator

from nyctala.schema.sanitize import clamp

TRUNCATED_TAG = "nyctala.truncated"
MAX_TAGS = 64
TAG_LIMIT = 128
DEFAULT_LIMIT = 1024

# Per-field character limits for free text; anything longer is truncated and tagged.
TEXT_LIMITS: dict[str, int] = {
    "event.original": 65_536,
    "process.command_line": 32_768,
    "url.path": 8_192,
    "url.query": 8_192,
    "file.path": 4_096,
    "user_agent.original": 2_048,
}


def _utc(value: datetime) -> datetime:
    return value.astimezone(UTC)


def _normalise_ip(value: str) -> str:
    ip = ipaddress.ip_address(value.strip())
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip.compressed


UtcDatetime = Annotated[AwareDatetime, AfterValidator(_utc)]
IP = Annotated[str, AfterValidator(_normalise_ip)]
Identifier = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")]
Sha256 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


def _text(alias: str) -> Any:
    return Field(default=None, alias=alias, max_length=TEXT_LIMITS.get(alias, DEFAULT_LIMIT))


class Event(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    timestamp: UtcDatetime = Field(alias="@timestamp")
    event_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()), alias="event.id", pattern=r"^[0-9a-f-]{36}$"
    )
    event_dataset: Identifier = Field(alias="event.dataset")
    event_category: str | None = _text("event.category")
    event_action: str | None = _text("event.action")
    event_outcome: Literal["success", "failure", "unknown"] | None = Field(
        default=None, alias="event.outcome"
    )
    event_original: str | None = _text("event.original")
    event_ingested: UtcDatetime = Field(
        default_factory=lambda: datetime.now(UTC), alias="event.ingested"
    )

    host_name: str | None = _text("host.name")
    sensor_id: Identifier = Field(alias="sensor.id")

    user_name: str | None = _text("user.name")
    user_target_name: str | None = _text("user.target.name")
    source_ip: IP | None = Field(default=None, alias="source.ip")
    destination_ip: IP | None = Field(default=None, alias="destination.ip")

    process_name: str | None = _text("process.name")
    process_command_line: str | None = _text("process.command_line")

    url_path: str | None = _text("url.path")
    url_query: str | None = _text("url.query")
    http_request_method: str | None = _text("http.request.method")
    http_response_status_code: int | None = Field(
        default=None, alias="http.response.status_code", ge=0, le=999
    )
    http_response_bytes: int | None = Field(default=None, alias="http.response.bytes", ge=0)
    user_agent_original: str | None = _text("user_agent.original")

    file_path: str | None = _text("file.path")
    tags: list[Annotated[str, Field(max_length=TAG_LIMIT)]] = Field(
        default_factory=list, max_length=MAX_TAGS
    )

    integrity_hash: Sha256 | None = Field(default=None, alias="integrity.hash")
    integrity_prev_hash: Sha256 | None = Field(default=None, alias="integrity.prev_hash")

    @model_validator(mode="before")
    @classmethod
    def _neutralise_text(cls, data: Any) -> Any:
        """Escape dangerous characters in every string and truncate long free text."""
        if not isinstance(data, dict):
            return data
        aliases: dict[str, str] = {name: f.alias or name for name, f in cls.model_fields.items()}
        out: dict[str, Any] = {}
        truncated = False
        for key, value in data.items():
            alias = aliases.get(key) or key
            if isinstance(value, str) and alias not in ("@timestamp", "event.ingested"):
                value, cut = clamp(value, TEXT_LIMITS.get(alias, DEFAULT_LIMIT))
                truncated |= cut
            out[key] = value
        tags_key = "tags"
        tags = out.get(tags_key)
        if isinstance(tags, list):
            clean_tags = []
            for tag in tags:
                if isinstance(tag, str):
                    tag, cut = clamp(tag, TAG_LIMIT)
                    truncated |= cut
                clean_tags.append(tag)
            out[tags_key] = clean_tags
        if truncated:
            current = out.get(tags_key) or []
            if not isinstance(current, list):
                return out
            if TRUNCATED_TAG not in current:
                out[tags_key] = [*current[: MAX_TAGS - 1], TRUNCATED_TAG]
        return out

    def to_record(self) -> dict[str, Any]:
        """Flat record keyed by ECS name, as stored."""
        return self.model_dump(by_alias=True)
