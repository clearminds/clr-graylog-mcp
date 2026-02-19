"""Configuration management for Graylog MCP server.

Supports two authentication methods:
- Token auth: Set GRAYLOG_TOKEN (recommended)
- Username/password auth: Set GRAYLOG_USERNAME + GRAYLOG_PASSWORD

Credential loading follows Clearminds pattern:
1. Environment variables (base/fallback)
2. ~/.config/graylog/credentials.json (takes priority)
"""

import base64
import json
import logging
from pathlib import Path
from typing import Any

from pydantic import Field, ConfigDict
from pydantic_settings import BaseSettings

logger = logging.getLogger(__name__)

CREDS_PATH = Path.home() / ".config" / "graylog" / "credentials.json"


class GraylogConfig(BaseSettings):
    """Graylog connection configuration."""

    endpoint: str = Field("http://localhost:9000", description="Graylog server endpoint URL")
    token: str = Field("", description="Graylog API token (preferred auth method)")
    username: str = Field("", description="Graylog username (basic auth)")
    password: str = Field("", description="Graylog password (basic auth)")
    verify_ssl: bool = Field(True, description="Verify SSL certificates")
    timeout: int = Field(60, description="Request timeout in seconds")

    model_config = ConfigDict(env_prefix="GRAYLOG_", case_sensitive=False)


class ServerConfig(BaseSettings):
    """MCP server configuration."""

    host: str = Field("0.0.0.0", description="Server host")
    port: int = Field(8000, description="Server port")
    log_level: str = Field("INFO", description="Logging level")

    model_config = ConfigDict(env_prefix="MCP_SERVER_", case_sensitive=False)


class Config:
    """Main configuration class with Clearminds credential loading."""

    def __init__(self):
        self.graylog = GraylogConfig()
        self.server = ServerConfig()
        self._load_credentials_file()

    def _load_credentials_file(self):
        """Override env vars with credentials.json if it exists."""
        if not CREDS_PATH.exists():
            return

        try:
            file_creds: dict[str, Any] = json.loads(CREDS_PATH.read_text())

            if "endpoint" in file_creds:
                self.graylog.endpoint = file_creds["endpoint"]
            if "token" in file_creds:
                self.graylog.token = file_creds["token"]
            if "username" in file_creds:
                self.graylog.username = file_creds["username"]
            if "password" in file_creds:
                self.graylog.password = file_creds["password"]
            if "verify_ssl" in file_creds:
                self.graylog.verify_ssl = file_creds["verify_ssl"]

            logger.info(f"Loaded credentials from {CREDS_PATH}")
        except (json.JSONDecodeError, KeyError) as e:
            logger.warning(f"Failed to load {CREDS_PATH}: {e}")

    @property
    def auth_headers(self) -> dict:
        """Get authentication headers for Graylog API.

        Token auth: uses token as username with literal "token" as password.
        Basic auth: uses username:password.
        """
        if self.graylog.token:
            credentials = f"{self.graylog.token}:token"
            encoded = base64.b64encode(credentials.encode()).decode()
            logger.info("Using token authentication")
            return {"Authorization": f"Basic {encoded}"}

        if self.graylog.username and self.graylog.password:
            credentials = f"{self.graylog.username}:{self.graylog.password}"
            encoded = base64.b64encode(credentials.encode()).decode()
            logger.info("Using username/password authentication")
            return {"Authorization": f"Basic {encoded}"}

        logger.warning("No authentication configured")
        return {}

    def has_auth(self) -> bool:
        """Check if any authentication is configured."""
        return bool(self.graylog.token or (self.graylog.username and self.graylog.password))


# Global configuration instance
config = Config()
