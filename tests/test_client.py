"""Tests for the Graylog API client with multi-instance support."""

from __future__ import annotations

from unittest.mock import Mock, patch

import pytest
import requests

from mcp_graylog.client import AggregationParams, GraylogClient, QueryParams
from mcp_graylog.config import GraylogInstance

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_instances() -> tuple[dict[str, GraylogInstance], str]:
    """Create a two-instance setup for testing."""
    return {
        "prod": GraylogInstance(
            name="prod",
            endpoint="https://graylog-prod.example.com",
            token="prod-token",
        ),
        "dev": GraylogInstance(
            name="dev",
            endpoint="https://graylog-dev.example.com",
            token="dev-token",
        ),
    }, "prod"


@pytest.fixture
def client() -> GraylogClient:
    """Create a GraylogClient with prod + dev instances (prod default)."""
    instances, default = _make_instances()
    return GraylogClient(instances, default)


# ---------------------------------------------------------------------------
# Instance management
# ---------------------------------------------------------------------------


class TestListInstances:
    """Tests for list_instances."""

    def test_returns_correct_data_with_default_flag(self, client: GraylogClient) -> None:
        """list_instances returns name, endpoint, and default flag for each instance."""
        result = client.list_instances()
        assert len(result) == 2

        prod = next(r for r in result if r["name"] == "prod")
        dev = next(r for r in result if r["name"] == "dev")

        assert prod["endpoint"] == "https://graylog-prod.example.com"
        assert prod["default"] is True

        assert dev["endpoint"] == "https://graylog-dev.example.com"
        assert dev["default"] is False


# ---------------------------------------------------------------------------
# _resolve
# ---------------------------------------------------------------------------


class TestResolve:
    """Tests for the _resolve method."""

    def test_none_returns_default_instance(self, client: GraylogClient) -> None:
        """_resolve(None) returns session and URL for the default (prod) instance."""
        session, base_url = client._resolve(None)
        assert base_url == "https://graylog-prod.example.com"
        assert isinstance(session, requests.Session)

    def test_explicit_name_returns_correct_instance(self, client: GraylogClient) -> None:
        """_resolve('dev') returns session and URL for the dev instance."""
        session, base_url = client._resolve("dev")
        assert base_url == "https://graylog-dev.example.com"
        assert isinstance(session, requests.Session)

    def test_nonexistent_raises_value_error(self, client: GraylogClient) -> None:
        """_resolve('nonexistent') raises ValueError with available instances."""
        with pytest.raises(ValueError, match="Unknown Graylog instance 'nonexistent'"):
            client._resolve("nonexistent")

    def test_sessions_are_cached(self, client: GraylogClient) -> None:
        """Calling _resolve twice for same instance returns the same Session object."""
        session1, _ = client._resolve("prod")
        session2, _ = client._resolve("prod")
        assert session1 is session2

    def test_different_instances_get_different_sessions(self, client: GraylogClient) -> None:
        """Different instance names produce different Session objects."""
        session_prod, _ = client._resolve("prod")
        session_dev, _ = client._resolve("dev")
        assert session_prod is not session_dev


# ---------------------------------------------------------------------------
# _parse_time_range
# ---------------------------------------------------------------------------


class TestParseTimeRange:
    """Tests for the _parse_time_range method."""

    def test_hours(self, client: GraylogClient) -> None:
        """Parses '2h' to 7200 seconds."""
        assert client._parse_time_range("2h") == {"range": 7200}

    def test_days(self, client: GraylogClient) -> None:
        """Parses '3d' to 259200 seconds."""
        assert client._parse_time_range("3d") == {"range": 259200}

    def test_weeks(self, client: GraylogClient) -> None:
        """Parses '1w' to 604800 seconds."""
        assert client._parse_time_range("1w") == {"range": 604800}

    def test_empty_string(self, client: GraylogClient) -> None:
        """Empty string returns empty dict."""
        assert client._parse_time_range("") == {}

    def test_none(self, client: GraylogClient) -> None:
        """None returns empty dict."""
        assert client._parse_time_range(None) == {}


# ---------------------------------------------------------------------------
# _make_request
# ---------------------------------------------------------------------------


class TestMakeRequest:
    """Tests for _make_request."""

    def test_success_default_instance(self, client: GraylogClient) -> None:
        """Successful GET against default instance returns parsed JSON."""
        # Force session creation so we can mock it
        session, _ = client._resolve("prod")

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"result": "ok"}
        mock_response.raise_for_status.return_value = None
        mock_response.headers = {"Content-Type": "application/json"}

        with patch.object(session, "request", return_value=mock_response) as mock_req:
            result = client._make_request("GET", "/api/test")

        assert result == {"result": "ok"}
        mock_req.assert_called_once()
        call_kwargs = mock_req.call_args
        assert "graylog-prod.example.com" in call_kwargs.kwargs.get("url", call_kwargs[1].get("url", ""))

    def test_uses_dev_instance_url(self, client: GraylogClient) -> None:
        """_make_request with instance='dev' hits the dev URL."""
        session, _ = client._resolve("dev")

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"instance": "dev"}
        mock_response.raise_for_status.return_value = None
        mock_response.headers = {"Content-Type": "application/json"}

        with patch.object(session, "request", return_value=mock_response) as mock_req:
            result = client._make_request("GET", "/api/test", instance="dev")

        assert result == {"instance": "dev"}
        call_kwargs = mock_req.call_args
        url = call_kwargs.kwargs.get("url", call_kwargs[1].get("url", ""))
        assert "graylog-dev.example.com" in url

    def test_204_returns_empty_dict(self, client: GraylogClient) -> None:
        """HTTP 204 No Content returns empty dict."""
        session, _ = client._resolve("prod")

        mock_response = Mock()
        mock_response.status_code = 204
        mock_response.text = ""
        mock_response.raise_for_status.return_value = None
        mock_response.headers = {"Content-Type": "application/json"}

        with patch.object(session, "request", return_value=mock_response):
            result = client._make_request("DELETE", "/api/test")

        assert result == {}

    def test_401_raises_http_error(self, client: GraylogClient) -> None:
        """HTTP 401 raises HTTPError with auth failure message."""
        session, _ = client._resolve("prod")

        mock_response = Mock()
        mock_response.status_code = 401
        mock_response.text = "Unauthorized"
        mock_response.headers = {"Content-Type": "application/json"}

        with patch.object(session, "request", return_value=mock_response):
            with pytest.raises(requests.exceptions.HTTPError, match="Authentication failed"):
                client._make_request("GET", "/api/test")


# ---------------------------------------------------------------------------
# Existing API methods (with instance param)
# ---------------------------------------------------------------------------


class TestSearchLogs:
    """Tests for search_logs."""

    def test_passes_through_correctly(self, client: GraylogClient) -> None:
        """search_logs builds correct params and calls _make_request."""
        with patch.object(client, "_make_request", return_value={"messages": [], "total_results": 0}) as mock:
            params = QueryParams(query="level:ERROR", time_range="1h", limit=10)
            result = client.search_logs(params)

        assert result == {"messages": [], "total_results": 0}
        mock.assert_called_once()
        call_args = mock.call_args
        assert call_args[0][0] == "GET"
        assert call_args[0][1] == "/api/search/universal/relative"

    def test_with_instance(self, client: GraylogClient) -> None:
        """search_logs passes instance to _make_request."""
        with patch.object(client, "_make_request", return_value={"messages": []}) as mock:
            params = QueryParams(query="*", time_range="1h")
            client.search_logs(params, instance="dev")

        call_kwargs = mock.call_args
        assert call_kwargs.kwargs.get("instance") == "dev" or call_kwargs[1].get("instance") == "dev"


class TestListStreams:
    """Tests for list_streams."""

    def test_returns_streams(self, client: GraylogClient) -> None:
        """list_streams extracts streams from response."""
        with patch.object(
            client, "_make_request",
            return_value={"streams": [{"id": "1", "title": "Test"}]},
        ) as mock:
            result = client.list_streams()

        assert result == [{"id": "1", "title": "Test"}]
        mock.assert_called_once_with("GET", "/api/streams", instance=None)


class TestGetStreamInfo:
    """Tests for get_stream_info."""

    def test_returns_stream(self, client: GraylogClient) -> None:
        """get_stream_info returns the response dict."""
        with patch.object(
            client, "_make_request",
            return_value={"id": "1", "title": "Test"},
        ) as mock:
            result = client.get_stream_info("1")

        assert result == {"id": "1", "title": "Test"}
        mock.assert_called_once_with("GET", "/api/streams/1", instance=None)


class TestGetSystemInfo:
    """Tests for get_system_info."""

    def test_returns_system_info(self, client: GraylogClient) -> None:
        """get_system_info returns the response dict."""
        with patch.object(
            client, "_make_request",
            return_value={"version": "5.2.0"},
        ) as mock:
            result = client.get_system_info()

        assert result == {"version": "5.2.0"}
        mock.assert_called_once_with("GET", "/api/system", instance=None)


class TestTestConnection:
    """Tests for test_connection."""

    def test_success(self, client: GraylogClient) -> None:
        """test_connection returns True on success."""
        session, _ = client._resolve("prod")

        with patch.object(session, "get") as mock_get, \
             patch.object(client, "get_system_info", return_value={"version": "5.2.0"}):
            mock_resp = Mock()
            mock_resp.status_code = 200
            mock_get.return_value = mock_resp
            assert client.test_connection() is True

    def test_failure(self, client: GraylogClient) -> None:
        """test_connection returns False on failure."""
        session, _ = client._resolve("prod")

        with patch.object(session, "get", side_effect=requests.exceptions.ConnectionError("fail")):
            assert client.test_connection() is False


# ---------------------------------------------------------------------------
# Notifications
# ---------------------------------------------------------------------------


class TestGetNotifications:
    """Tests for get_notifications."""

    def test_returns_list(self, client: GraylogClient) -> None:
        """get_notifications extracts notifications list from response."""
        with patch.object(
            client, "_make_request",
            return_value={"notifications": [{"type": "es_node_disk_watermark"}]},
        ) as mock:
            result = client.get_notifications()

        assert result == [{"type": "es_node_disk_watermark"}]
        mock.assert_called_once_with("GET", "/api/system/notifications", instance=None)

    def test_empty_response(self, client: GraylogClient) -> None:
        """get_notifications returns empty list when key missing."""
        with patch.object(client, "_make_request", return_value={}):
            assert client.get_notifications() == []


class TestDismissNotification:
    """Tests for dismiss_notification."""

    def test_calls_delete(self, client: GraylogClient) -> None:
        """dismiss_notification sends DELETE to correct endpoint."""
        with patch.object(client, "_make_request", return_value={}) as mock:
            client.dismiss_notification("es_node_disk_watermark")

        mock.assert_called_once_with(
            "DELETE",
            "/api/system/notifications/es_node_disk_watermark",
            instance=None,
        )


# ---------------------------------------------------------------------------
# Sidecars
# ---------------------------------------------------------------------------


class TestListSidecars:
    """Tests for list_sidecars."""

    def test_returns_list(self, client: GraylogClient) -> None:
        """list_sidecars extracts sidecars list from response."""
        with patch.object(
            client, "_make_request",
            return_value={"sidecars": [{"node_id": "abc"}]},
        ) as mock:
            result = client.list_sidecars()

        assert result == [{"node_id": "abc"}]
        mock.assert_called_once_with("GET", "/api/sidecars", instance=None)


class TestGetSidecar:
    """Tests for get_sidecar."""

    def test_returns_dict(self, client: GraylogClient) -> None:
        """get_sidecar returns the response dict."""
        with patch.object(
            client, "_make_request",
            return_value={"node_id": "abc", "node_name": "server1"},
        ) as mock:
            result = client.get_sidecar("abc")

        assert result == {"node_id": "abc", "node_name": "server1"}
        mock.assert_called_once_with("GET", "/api/sidecars/abc", instance=None)


class TestUpdateSidecarTags:
    """Tests for update_sidecar_tags."""

    def test_sends_put_with_tags(self, client: GraylogClient) -> None:
        """update_sidecar_tags sends PUT with tags payload."""
        with patch.object(client, "_make_request", return_value={}) as mock:
            client.update_sidecar_tags("abc", ["linux", "webserver"])

        mock.assert_called_once_with(
            "PUT",
            "/api/sidecars/abc/tags",
            data={"tags": ["linux", "webserver"]},
            instance=None,
        )


class TestAssignSidecarConfigurations:
    """Tests for assign_sidecar_configurations."""

    def test_sends_put_with_nodes(self, client: GraylogClient) -> None:
        """assign_sidecar_configurations sends PUT with nodes payload."""
        nodes = [{"node_id": "abc", "collector_configuration_id": "cfg1"}]
        with patch.object(client, "_make_request", return_value={}) as mock:
            client.assign_sidecar_configurations(nodes)

        mock.assert_called_once_with(
            "PUT",
            "/api/sidecars/configurations",
            data={"nodes": nodes},
            instance=None,
        )


class TestListSidecarConfigurations:
    """Tests for list_sidecar_configurations."""

    def test_returns_list(self, client: GraylogClient) -> None:
        """list_sidecar_configurations extracts configurations from response."""
        with patch.object(
            client, "_make_request",
            return_value={"configurations": [{"id": "cfg1", "name": "filebeat"}]},
        ) as mock:
            result = client.list_sidecar_configurations()

        assert result == [{"id": "cfg1", "name": "filebeat"}]
        mock.assert_called_once_with("GET", "/api/sidecar/configurations", instance=None)


class TestGetSidecarConfiguration:
    """Tests for get_sidecar_configuration."""

    def test_returns_dict(self, client: GraylogClient) -> None:
        """get_sidecar_configuration returns the response dict."""
        with patch.object(
            client, "_make_request",
            return_value={"id": "cfg1", "name": "filebeat"},
        ) as mock:
            result = client.get_sidecar_configuration("cfg1")

        assert result == {"id": "cfg1", "name": "filebeat"}
        mock.assert_called_once_with("GET", "/api/sidecar/configurations/cfg1", instance=None)


class TestListCollectors:
    """Tests for list_collectors."""

    def test_returns_list(self, client: GraylogClient) -> None:
        """list_collectors extracts collectors from response."""
        with patch.object(
            client, "_make_request",
            return_value={"collectors": [{"id": "col1", "name": "filebeat"}]},
        ) as mock:
            result = client.list_collectors()

        assert result == [{"id": "col1", "name": "filebeat"}]
        mock.assert_called_once_with("GET", "/api/sidecar/collectors", instance=None)


class TestSidecarAction:
    """Tests for sidecar_action."""

    def test_sends_put_with_action_and_collector(self, client: GraylogClient) -> None:
        """sidecar_action sends PUT with action and collector_id."""
        with patch.object(client, "_make_request", return_value={}) as mock:
            client.sidecar_action("abc", "restart", "col1")

        mock.assert_called_once_with(
            "PUT",
            "/api/sidecars/abc/action",
            data={"action": "restart", "collector_id": "col1"},
            instance=None,
        )


class TestGetSidecarsAdministration:
    """Tests for get_sidecars_administration."""

    def test_returns_dict(self, client: GraylogClient) -> None:
        """get_sidecars_administration returns the response dict."""
        with patch.object(
            client, "_make_request",
            return_value={"sidecars": [], "pagination": {}},
        ) as mock:
            result = client.get_sidecars_administration()

        assert result == {"sidecars": [], "pagination": {}}
        mock.assert_called_once_with("GET", "/api/sidecars/administration", instance=None)


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class TestQueryParams:
    """Tests for the QueryParams model."""

    def test_creation(self) -> None:
        """QueryParams accepts all fields."""
        params = QueryParams(query="test query", time_range="1h", limit=50)
        assert params.query == "test query"
        assert params.time_range == "1h"
        assert params.limit == 50
        assert params.offset == 0
        assert params.sort_direction == "desc"

    def test_defaults(self) -> None:
        """QueryParams uses correct defaults."""
        params = QueryParams(query="test")
        assert params.limit == 50
        assert params.offset == 0
        assert params.sort_direction == "desc"
        assert params.time_range == "1h"


class TestAggregationParams:
    """Tests for the AggregationParams model."""

    def test_creation(self) -> None:
        """AggregationParams accepts all fields."""
        params = AggregationParams(type="terms", field="level", size=20)
        assert params.type == "terms"
        assert params.field == "level"
        assert params.size == 20
        assert params.interval is None

    def test_with_interval(self) -> None:
        """AggregationParams accepts interval for date histograms."""
        params = AggregationParams(
            type="date_histogram", field="timestamp", size=10, interval="1h"
        )
        assert params.type == "date_histogram"
        assert params.field == "timestamp"
        assert params.interval == "1h"
