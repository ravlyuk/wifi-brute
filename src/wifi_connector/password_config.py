from __future__ import annotations

import os
from functools import lru_cache
from importlib.resources import files
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, ValidationError, field_validator

_PASSWORDS_ENV_VAR = "WIFI_CONNECT_PASSWORDS_FILE"
_USER_CONFIG_PATH = (
    Path.home() / "Library" / "Application Support" / "Wi-Fi Connect" / "common_passwords.yaml"
)
_SHARED_PASSWORDS_FILENAME = "common_passwords.yaml"
_MIN_PASSWORD_LENGTH = 8
_MAX_PASSWORD_LENGTH = 63


class PasswordListConfig(BaseModel):
    default_password: str = Field(min_length=_MIN_PASSWORD_LENGTH, max_length=_MAX_PASSWORD_LENGTH)
    passwords: list[str] = Field(min_length=1)

    @field_validator("default_password", mode="before")
    @classmethod
    def strip_default_password(cls, value: object) -> object:
        if isinstance(value, str):
            return value.strip()
        return value

    @field_validator("passwords", mode="before")
    @classmethod
    def strip_password_items(cls, value: object) -> object:
        if not isinstance(value, list):
            return value
        return [item.strip() if isinstance(item, str) else item for item in value]

    @field_validator("passwords")
    @classmethod
    def validate_password_lengths(cls, passwords: list[str]) -> list[str]:
        for password in passwords:
            if len(password) < _MIN_PASSWORD_LENGTH or len(password) > _MAX_PASSWORD_LENGTH:
                raise ValueError(
                    f"password must be {_MIN_PASSWORD_LENGTH}-{_MAX_PASSWORD_LENGTH} characters: {password!r}"
                )
        return passwords


def shared_passwords_path() -> Path | None:
    module_dir = Path(__file__).resolve().parent
    for parent in module_dir.parents:
        candidate = parent / _SHARED_PASSWORDS_FILENAME
        if candidate.is_file():
            return candidate
        if (parent / "pyproject.toml").is_file():
            break
    return None


def bundled_passwords_path() -> Path:
    return Path(str(files("wifi_connector") / _SHARED_PASSWORDS_FILENAME))


def resolve_passwords_path() -> Path:
    env_path = os.environ.get(_PASSWORDS_ENV_VAR, "").strip()
    if env_path:
        return Path(env_path).expanduser()
    if _USER_CONFIG_PATH.is_file():
        return _USER_CONFIG_PATH
    shared_path = shared_passwords_path()
    if shared_path is not None:
        return shared_path
    return bundled_passwords_path()


def _read_yaml_mapping(path: Path) -> dict[str, Any]:
    raw_text = path.read_text(encoding="utf-8")
    parsed = yaml.safe_load(raw_text)
    if not isinstance(parsed, dict):
        raise ValueError(f"{path} must contain a YAML mapping at the root")
    return parsed


def load_password_config(*, path: Path | None = None) -> PasswordListConfig:
    config_path = path or resolve_passwords_path()
    try:
        payload = _read_yaml_mapping(config_path)
        return PasswordListConfig.model_validate(payload)
    except (OSError, yaml.YAMLError, ValidationError, ValueError) as error:
        raise ValueError(f"Failed to load passwords from {config_path}: {error}") from error


@lru_cache(maxsize=1)
def get_password_config() -> PasswordListConfig:
    return load_password_config()


def reload_password_config() -> PasswordListConfig:
    get_password_config.cache_clear()
    return get_password_config()


def common_test_passwords() -> tuple[str, ...]:
    return tuple(get_password_config().passwords)
