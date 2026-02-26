"""Tests for Graylog MCP config with multi-instance support."""

import base64
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from mcp_graylog.config import CREDS_PATH, GraylogInstance, Settings


class TestGraylogInstance:
    """Test GraylogInstance auth and properties."""

    def test_token_auth_headers(self) -> None:
        """Token auth encodes '{token}:token' as Basic header."""
        inst = GraylogInstance(
            name="prod",
            endpoint="https://graylog.example.com",
            token="my-api-token",
        )
        expected = base64.b64encode(b"my-api-token:token").decode()
        assert inst.auth_headers == {"Authorization": f"Basic {expected}"}

    def test_basic_auth_headers(self) -> None:
        """Username/password auth encodes '{user}:{pass}' as Basic header."""
        inst = GraylogInstance(
            name="dev",
            endpoint="https://graylog.example.com",
            username="admin",
            password="secret",
        )
        expected = base64.b64encode(b"admin:secret").decode()
        assert inst.auth_headers == {"Authorization": f"Basic {expected}"}

    def test_token_takes_precedence_over_basic(self) -> None:
        """When both token and username/password are set, token wins."""
        inst = GraylogInstance(
            name="both",
            endpoint="https://graylog.example.com",
            token="my-token",
            username="admin",
            password="secret",
        )
        expected = base64.b64encode(b"my-token:token").decode()
        assert inst.auth_headers == {"Authorization": f"Basic {expected}"}

    def test_no_auth_headers(self) -> None:
        """No auth configured returns empty dict."""
        inst = GraylogInstance(
            name="noauth",
            endpoint="https://graylog.example.com",
        )
        assert inst.auth_headers == {}

    def test_has_auth_with_token(self) -> None:
        """has_auth is True when token is set."""
        inst = GraylogInstance(
            name="t",
            endpoint="https://graylog.example.com",
            token="tok",
        )
        assert inst.has_auth is True

    def test_has_auth_with_basic(self) -> None:
        """has_auth is True when username and password are set."""
        inst = GraylogInstance(
            name="b",
            endpoint="https://graylog.example.com",
            username="u",
            password="p",
        )
        assert inst.has_auth is True

    def test_has_auth_false(self) -> None:
        """has_auth is False when no auth is configured."""
        inst = GraylogInstance(
            name="none",
            endpoint="https://graylog.example.com",
        )
        assert inst.has_auth is False

    def test_has_auth_partial_basic(self) -> None:
        """has_auth is False with only username (no password)."""
        inst = GraylogInstance(
            name="partial",
            endpoint="https://graylog.example.com",
            username="admin",
        )
        assert inst.has_auth is False

    def test_default_values(self) -> None:
        """Default verify_ssl and timeout values are correct."""
        inst = GraylogInstance(name="defaults", endpoint="http://localhost:9000")
        assert inst.verify_ssl is True
        assert inst.timeout == 60


class TestSettings:
    """Test Settings env var loading and instance loading."""

    def test_load_from_env_vars(self) -> None:
        """Env vars create a 'default' instance."""
        env = {
            "GRAYLOG_ENDPOINT": "https://graylog.env.com",
            "GRAYLOG_TOKEN": "env-token",
        }
        with patch.dict("os.environ", env, clear=False):
            settings = Settings()
            # Mock away creds file
            with patch("mcp_graylog.config.CREDS_PATH", Path("/nonexistent/path")):
                instances = settings.load_instances()

        assert "default" in instances
        assert instances["default"].endpoint == "https://graylog.env.com"
        assert instances["default"].token == "env-token"
        assert instances["default"].name == "default"

    def test_load_single_from_file(self, tmp_path: Path) -> None:
        """Single-instance credentials.json creates a 'default' instance."""
        creds_file = tmp_path / "credentials.json"
        creds_file.write_text(json.dumps({
            "endpoint": "https://graylog.file.com",
            "token": "file-token",
            "verify_ssl": False,
        }))

        with patch("mcp_graylog.config.CREDS_PATH", creds_file):
            settings = Settings()
            instances = settings.load_instances()

        assert "default" in instances
        assert instances["default"].endpoint == "https://graylog.file.com"
        assert instances["default"].token == "file-token"
        assert instances["default"].verify_ssl is False

    def test_load_multi_from_file(self, tmp_path: Path) -> None:
        """Multi-instance credentials.json loads all instances."""
        creds_file = tmp_path / "credentials.json"
        creds_file.write_text(json.dumps({
            "instances": {
                "prod": {
                    "endpoint": "https://graylog-prod.com",
                    "token": "prod-token",
                },
                "dev": {
                    "endpoint": "https://graylog-dev.com",
                    "username": "admin",
                    "password": "devpass",
                },
            },
            "default": "prod",
        }))

        with patch("mcp_graylog.config.CREDS_PATH", creds_file):
            settings = Settings()
            instances = settings.load_instances()

        assert len(instances) == 2
        assert "prod" in instances
        assert "dev" in instances
        assert instances["prod"].token == "prod-token"
        assert instances["dev"].username == "admin"
        assert instances["dev"].password == "devpass"

    def test_get_default_name_from_file(self, tmp_path: Path) -> None:
        """get_default_name reads 'default' key from credentials.json."""
        creds_file = tmp_path / "credentials.json"
        creds_file.write_text(json.dumps({
            "instances": {
                "prod": {"endpoint": "https://prod.com", "token": "t"},
                "dev": {"endpoint": "https://dev.com", "token": "t"},
            },
            "default": "prod",
        }))

        with patch("mcp_graylog.config.CREDS_PATH", creds_file):
            settings = Settings()
            assert settings.get_default_name() == "prod"

    def test_get_default_name_fallback_to_first_instance(self, tmp_path: Path) -> None:
        """get_default_name falls back to first instance key if no 'default' key."""
        creds_file = tmp_path / "credentials.json"
        creds_file.write_text(json.dumps({
            "instances": {
                "alpha": {"endpoint": "https://alpha.com", "token": "t"},
                "beta": {"endpoint": "https://beta.com", "token": "t"},
            },
        }))

        with patch("mcp_graylog.config.CREDS_PATH", creds_file):
            settings = Settings()
            assert settings.get_default_name() == "alpha"

    def test_get_default_name_no_file(self) -> None:
        """get_default_name returns 'default' when no credentials file exists."""
        with patch("mcp_graylog.config.CREDS_PATH", Path("/nonexistent/path")):
            settings = Settings()
            assert settings.get_default_name() == "default"

    def test_file_overrides_env_vars(self, tmp_path: Path) -> None:
        """Credentials file overrides env var instances (file takes priority)."""
        creds_file = tmp_path / "credentials.json"
        creds_file.write_text(json.dumps({
            "endpoint": "https://graylog.file.com",
            "token": "file-token",
        }))

        env = {
            "GRAYLOG_ENDPOINT": "https://graylog.env.com",
            "GRAYLOG_TOKEN": "env-token",
        }
        with patch.dict("os.environ", env, clear=False):
            with patch("mcp_graylog.config.CREDS_PATH", creds_file):
                settings = Settings()
                instances = settings.load_instances()

        # File should override the env var instance
        assert "default" in instances
        assert instances["default"].endpoint == "https://graylog.file.com"
        assert instances["default"].token == "file-token"

    def test_multi_file_clears_env_instances(self, tmp_path: Path) -> None:
        """Multi-instance file replaces any env-var-based instances entirely."""
        creds_file = tmp_path / "credentials.json"
        creds_file.write_text(json.dumps({
            "instances": {
                "prod": {
                    "endpoint": "https://graylog-prod.com",
                    "token": "prod-tok",
                },
            },
            "default": "prod",
        }))

        env = {
            "GRAYLOG_ENDPOINT": "https://graylog.env.com",
            "GRAYLOG_TOKEN": "env-token",
        }
        with patch.dict("os.environ", env, clear=False):
            with patch("mcp_graylog.config.CREDS_PATH", creds_file):
                settings = Settings()
                instances = settings.load_instances()

        # Only the file instances should exist, env "default" should be gone
        assert len(instances) == 1
        assert "prod" in instances
        assert instances["prod"].token == "prod-tok"

    def test_empty_str_to_false_validator(self) -> None:
        """Empty string env vars for bool fields resolve to False."""
        env = {
            "GRAYLOG_VERIFY_SSL": "",
            "GRAYLOG_READ_ONLY": "",
        }
        with patch.dict("os.environ", env, clear=False):
            settings = Settings()
        assert settings.graylog_verify_ssl is False
        assert settings.graylog_read_only is False

    def test_no_instances_without_auth(self) -> None:
        """No instances created from env vars when no auth is configured."""
        env = {
            "GRAYLOG_ENDPOINT": "https://graylog.example.com",
            # No token, no username/password
        }
        with patch.dict("os.environ", env, clear=False):
            with patch("mcp_graylog.config.CREDS_PATH", Path("/nonexistent/path")):
                settings = Settings()
                instances = settings.load_instances()

        assert len(instances) == 0
