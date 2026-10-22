"""Alert model.

An alert is written once and never modified. It carries everything needed to
explain it: the rule and its ATT&CK techniques, the events that caused it, the
entities involved and the risk accumulated by those entities when it fired.
Entity risk and incidents are computed from alerts, not stored.
"""

import uuid
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from nyctala.schema.event import UtcDatetime

LEVEL_SCORES = {"informational": 0, "low": 10, "medium": 25, "high": 50, "critical": 75}


class Alert(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    alert_id: str = Field(default_factory=lambda: str(uuid.uuid4()), alias="alert.id")
    created: UtcDatetime = Field(default_factory=lambda: datetime.now(UTC), alias="alert.created")
    kind: Literal["detection", "correlation", "risk"] = Field(alias="alert.kind")
    rule_id: str = Field(alias="rule.id")
    rule_name: str | None = Field(default=None, alias="rule.name")
    rule_title: str = Field(alias="rule.title")
    rule_level: str = Field(alias="rule.level")
    techniques: list[str] = Field(default_factory=list, alias="threat.technique.id")
    first: UtcDatetime = Field(alias="alert.first")
    last: UtcDatetime = Field(alias="alert.last")
    group: str = Field(default="{}", alias="alert.group")  # JSON of the group-by values
    event_ids: list[str] = Field(default_factory=list, alias="alert.event_ids")
    related_alert_ids: list[str] = Field(default_factory=list, alias="related.alert_ids")
    entities: list[str] = Field(default_factory=list, alias="alert.entities")
    risk_score: int = Field(default=0, ge=0, alias="risk.score")
    risk_accumulated: int = Field(default=0, ge=0, alias="risk.accumulated")
    risk_entity: str | None = Field(default=None, alias="risk.entity")
    explanation: str = Field(default="", alias="alert.explanation")

    def to_record(self) -> dict[str, Any]:
        return self.model_dump(by_alias=True)
