"""Device-independent domain models."""

from __future__ import annotations

from typing import Generic, Self, TypeVar

from pydantic import AnyHttpUrl, BaseModel, ConfigDict, Field, SecretStr, model_validator


class DeviceIdentity(BaseModel):
    """Identity values reported by a SwOS device."""

    model_config = ConfigDict(frozen=True)

    firmware_family: str = Field(min_length=1)
    product_code: str = Field(min_length=1)
    firmware_version: str = Field(min_length=1)
    marketing_name: str | None = None
    build_id: str | None = None


class DeviceConnection(BaseModel):
    """Connection details shared by all device adapters."""

    model_config = ConfigDict(frozen=True)

    url: AnyHttpUrl
    username: str = "admin"
    password: SecretStr = SecretStr("")
    timeout: float = Field(default=10.0, gt=0)
    verify_tls: bool = True


class DeviceCapabilities(BaseModel):
    """Capabilities exposed by a concrete model and firmware combination."""

    model_config = ConfigDict(frozen=True)

    features: frozenset[str] = frozenset()

    def supports(self, feature: str) -> bool:
        """Return whether a named feature is supported."""

        return feature in self.features


class SystemInfo(BaseModel):
    """Device-independent system information."""

    model_config = ConfigDict(frozen=True)

    identity: DeviceIdentity
    name: str
    uptime_seconds: int = Field(ge=0)
    current_ip: str | None = None
    static_ip: str | None = None
    mac_address: str | None = None
    serial_number: str | None = None


class PortInfo(BaseModel):
    """Device-independent operational and basic configured port state."""

    model_config = ConfigDict(frozen=True)

    number: int = Field(ge=1)
    name: str
    enabled: bool
    link_up: bool
    speed_mbps: int | None = Field(default=None, ge=1)
    full_duplex: bool | None = None
    auto_negotiation: bool
    flow_control: bool

    @model_validator(mode="after")
    def validate_operational_state(self) -> Self:
        if self.link_up and (self.speed_mbps is None or self.full_duplex is None):
            raise ValueError("link-up ports require speed and duplex state")
        if not self.link_up and (self.speed_mbps is not None or self.full_duplex is not None):
            raise ValueError("link-down ports cannot have operational speed or duplex state")
        return self


ResultValue = TypeVar("ResultValue")


class OperationResult(BaseModel, Generic[ResultValue]):
    """Result of a read or idempotent configuration operation."""

    model_config = ConfigDict(frozen=True)

    changed: bool = False
    value: ResultValue
