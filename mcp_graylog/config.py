"""Configuration for Graylog MCP Server.

Credential loading follows the Clearminds standard pattern:
1. Load from environment variables FIRST (base/fallback)
2. Override with ~/.config/graylog/credentials.json (takes priority)

Supports single-instance and multi-instance configurations.
"""

import base64
import json
import logging
from pathlib import Path
from typing import Any

from pydantic import field_validator
from pydantic_settings import BaseSettings

logger = logging.getLogger(__name__)

CREDS_PATH = Path.home() / ".config" / "graylog" / "credentials.json"


class GraylogInstance:
    """A single Graylog instance.

    Attributes:
        name: Identifier for this instance.
        endpoint: Graylog server endpoint URL.
        token: API token for token-based authentication (preferred).
        username: Username for basic authentication.
        password: Password for basic authentication.
        verify_ssl: Whether to verify SSL certificates.
        timeout: Request timeout in seconds.
    """

    def __init__(
        self,
        name: str,
        endpoint: str,
        token: str = "",
        username: str = "",
        password: str = "",
        verify_ssl: bool = True,
        timeout: int = 60,
    ) -> None:
        self.name = name
        self.endpoint = endpoint
        self.token = token
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.timeout = timeout

    @property
    def auth_headers(self) -> dict[str, str]:
        """Get authentication headers for Graylog API.

        Token auth: uses token as username with literal "token" as password.
        Basic auth: uses username:password.

        Returns:
            Dictionary with Authorization header, or empty dict if no auth.
        """
        if self.token:
            credentials = f"{self.token}:token"
            encoded = base64.b64encode(credentials.encode()).decode()
            return {"Authorization": f"Basic {encoded}"}

        if self.username and self.password:
            credentials = f"{self.username}:{self.password}"
            encoded = base64.b64encode(credentials.encode()).decode()
            return {"Authorization": f"Basic {encoded}"}

        return {}

    @property
    def has_auth(self) -> bool:
        """Check if any authentication is configured."""
        return bool(self.token or (self.username and self.password))


class Settings(BaseSettings):
    """Settings for the Graylog MCP server.

    Attributes:
        graylog_endpoint: Graylog endpoint for single-instance config.
        graylog_token: API token for single-instance config.
        graylog_username: Username for basic auth.
        graylog_password: Password for basic auth.
        graylog_verify_ssl: Verify SSL certificates.
        graylog_timeout: Request timeout in seconds.
        graylog_read_only: Run in read-only mode (hide write tools).
        graylog_transport: MCP transport type.
        graylog_log_level: Logging level.
    """

    graylog_endpoint: str = "http://localhost:9000"
    graylog_token: str = ""
    graylog_username: str = ""
    graylog_password: str = ""
    graylog_verify_ssl: bool = True
    graylog_timeout: int = 60
    graylog_read_only: bool = False
    graylog_transport: str = "stdio"
    graylog_log_level: str = "INFO"

    @field_validator("graylog_verify_ssl", "graylog_read_only", mode="before")
    @classmethod
    def _empty_str_to_false(cls, v: Any) -> Any:
        if v == "":
            return False
        return v

    model_config = {"env_prefix": ""}

    def load_instances(self) -> dict[str, GraylogInstance]:
        """Load Graylog instances from env vars or credentials.json.

        Supports two formats in credentials.json:

        Single instance:
            {"endpoint": "...", "token": "..."}

        Multi-instance:
            {
                "instances": {
                    "prod": {"endpoint": "...", "token": "..."},
                    "dev": {"endpoint": "...", "username": "...", "password": "..."}
                },
                "default": "prod"
            }

        Returns:
            Mapping of instance names to GraylogInstance objects.
        """
        instances: dict[str, GraylogInstance] = {}

        # 1. FIRST: Load from environment variables (base/fallback)
        has_token = bool(self.graylog_token)
        has_basic = bool(self.graylog_username and self.graylog_password)
        if has_token or has_basic:
            instances["default"] = GraylogInstance(
                name="default",
                endpoint=self.graylog_endpoint,
                token=self.graylog_token,
                username=self.graylog_username,
                password=self.graylog_password,
                verify_ssl=self.graylog_verify_ssl,
                timeout=self.graylog_timeout,
            )

        # 2. THEN: Override with credentials.json file (takes priority)
        if CREDS_PATH.exists():
            try:
                data: dict[str, Any] = json.loads(CREDS_PATH.read_text())

                if "instances" in data:
                    instances.clear()
                    for name, cfg in data["instances"].items():
                        instances[name] = GraylogInstance(
                            name=name,
                            endpoint=cfg.get("endpoint", "http://localhost:9000"),
                            token=cfg.get("token", ""),
                            username=cfg.get("username", ""),
                            password=cfg.get("password", ""),
                            verify_ssl=cfg.get("verify_ssl", True),
                            timeout=cfg.get("timeout", 60),
                        )
                    logger.info(
                        "Loaded %d Graylog instance(s) from %s", len(instances), CREDS_PATH
                    )
                elif data.get("endpoint") or data.get("token") or data.get("username"):
                    instances["default"] = GraylogInstance(
                        name="default",
                        endpoint=data.get("endpoint", "http://localhost:9000"),
                        token=data.get("token", ""),
                        username=data.get("username", ""),
                        password=data.get("password", ""),
                        verify_ssl=data.get("verify_ssl", True),
                        timeout=data.get("timeout", 60),
                    )
                    logger.info("Loaded Graylog credentials from %s", CREDS_PATH)
            except (json.JSONDecodeError, KeyError) as e:
                logger.warning("Failed to load %s: %s", CREDS_PATH, e)

        if not instances:
            logger.warning(
                "No Graylog instances configured. Set GRAYLOG_TOKEN or "
                "GRAYLOG_USERNAME/GRAYLOG_PASSWORD env vars or create %s",
                CREDS_PATH,
            )

        return instances

    def get_default_name(self) -> str:
        """Get the default instance name from credentials.json.

        Returns:
            The default instance name from the file, or the first instance
            key, or "default" as a last resort.
        """
        if CREDS_PATH.exists():
            try:
                data: dict[str, Any] = json.loads(CREDS_PATH.read_text())
                if "default" in data:
                    return data["default"]
                if "instances" in data:
                    return next(iter(data["instances"]))
            except (json.JSONDecodeError, KeyError):
                pass
        return "default"
