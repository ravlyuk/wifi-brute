from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, field_validator


class SecurityKind(str, Enum):
    OPEN = "open"
    PERSONAL = "personal"
    ENTERPRISE = "enterprise"
    UNKNOWN = "unknown"


class WifiNetwork(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    ssid: str = Field(min_length=1, max_length=32)
    security: SecurityKind = SecurityKind.UNKNOWN
    rssi_dbm: int | None = None
    is_current: bool = False

    @field_validator("ssid")
    @classmethod
    def reject_control_chars(cls, value: str) -> str:
        if any(ord(char) < 32 for char in value):
            raise ValueError("SSID must not contain control characters")
        return value


class JoinRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    ssid: str = Field(min_length=1, max_length=32)
    password: str = Field(min_length=8, max_length=63)
    interface: str | None = Field(default=None, pattern=r"^en\d+$")

    @field_validator("ssid")
    @classmethod
    def reject_control_chars(cls, value: str) -> str:
        if any(ord(char) < 32 for char in value):
            raise ValueError("SSID must not contain control characters")
        return value


class JoinResult(BaseModel):
    is_connected: bool
    ssid: str
    interface: str
    message: str
    password: str | None = None


class TestAllProgress(BaseModel):
    current: int
    total: int
    ssid: str
    elapsed_seconds: float
    average_seconds_per_network: float
    completed: list[JoinResult] = Field(default_factory=list)
    is_active: bool = False
    latest_result: JoinResult | None = None
    successful: list[JoinResult] = Field(default_factory=list)
    password_current: int = 0
    password_total: int = 0
    current_password: str | None = None


class TestAllResult(BaseModel):
    results: list[JoinResult]
    elapsed_seconds: float
    average_seconds_per_network: float
    was_stopped: bool = False

    @property
    def successful(self) -> list[JoinResult]:
        return [result for result in self.results if result.is_connected]

    @property
    def failed(self) -> list[JoinResult]:
        return [result for result in self.results if not result.is_connected]

    @property
    def successful_count(self) -> int:
        return len(self.successful)

    @property
    def failed_count(self) -> int:
        return len(self.failed)
