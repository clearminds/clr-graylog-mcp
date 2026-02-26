"""Graylog API client for MCP server.

Supports multiple Graylog instances with lazy session creation and a
default-instance fallback.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any
from urllib.parse import urljoin

import requests
from pydantic import BaseModel, Field

from .config import GraylogInstance

logger = logging.getLogger(__name__)


class QueryParams(BaseModel):
    """Query parameters for log search.

    Attributes:
        query: Elasticsearch-syntax search query.
        time_range: Relative or absolute time range string.
        fields: Specific fields to return in results.
        limit: Maximum number of results to return.
        offset: Pagination offset for results.
        sort: Field name to sort results by.
        sort_direction: Sort order, either "asc" or "desc".
        stream_id: Restrict search to a specific stream.
        decorate: Whether to decorate messages with additional metadata.
        filter: Additional filter query appended to the search.
        highlight: Enable or disable result highlighting.
    """

    query: str = Field(..., description="Search query")
    time_range: str | None = Field(
        "1h",
        description="Time range (e.g., '1h', '24h', '7d'). Defaults to '1h' if not specified.",
    )
    fields: list[str] | None = Field(None, description="Fields to return")
    limit: int = Field(50, description="Maximum number of results")
    offset: int = Field(0, description="Result offset")
    sort: str | None = Field(None, description="Sort field")
    sort_direction: str = Field("desc", description="Sort direction")
    stream_id: str | None = Field(None, description="Stream ID to search in")
    decorate: bool | None = Field(
        None, description="Whether to decorate messages (default: true)"
    )
    filter: str | None = Field(None, description="Additional filter query")
    highlight: bool | None = Field(
        None, description="Enable/disable result highlighting"
    )


class AggregationParams(BaseModel):
    """Aggregation parameters for log analysis.

    Attributes:
        type: Aggregation type such as "terms", "date_histogram", or "stats".
        field: Field name to aggregate on.
        size: Number of aggregation buckets to return.
        interval: Time interval for date histogram aggregations.
    """

    type: str = Field(..., description="Aggregation type (terms, date_histogram, etc.)")
    field: str = Field(..., description="Field to aggregate on")
    size: int = Field(10, description="Number of buckets")
    interval: str | None = Field(
        None, description="Time interval for date histograms"
    )


class GraylogClient:
    """Client for interacting with one or more Graylog REST APIs.

    Manages multiple named Graylog instances, lazily creating one
    ``requests.Session`` per instance with the correct auth headers.

    Args:
        instances: Mapping of instance name to ``GraylogInstance``.
        default_name: Name of the instance to use when none is specified.

    Attributes:
        instances: The instance registry.
        default_name: Name of the default instance.
    """

    def __init__(
        self,
        instances: dict[str, GraylogInstance],
        default_name: str,
    ) -> None:
        self.instances = instances
        self.default_name = default_name
        self._sessions: dict[str, requests.Session] = {}

    # ------------------------------------------------------------------
    # Instance helpers
    # ------------------------------------------------------------------

    def _resolve(
        self, instance: str | None = None
    ) -> tuple[requests.Session, str]:
        """Return ``(session, base_url)`` for the named (or default) instance.

        Sessions are created lazily on first access and cached for reuse.

        Args:
            instance: Instance name, or ``None`` to use the default.

        Returns:
            Tuple of the pre-configured ``requests.Session`` and the
            base URL for the resolved instance.

        Raises:
            ValueError: If the requested instance name is not registered.
        """
        name = instance or self.default_name
        if name not in self.instances:
            available = ", ".join(sorted(self.instances))
            raise ValueError(
                f"Unknown Graylog instance '{name}'. Available: {available}"
            )
        if name not in self._sessions:
            inst = self.instances[name]
            session = requests.Session()
            session.headers.update(inst.auth_headers)
            session.headers.update(
                {
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "X-Requested-By": "XMLHttpRequest",
                }
            )
            session.verify = inst.verify_ssl
            self._sessions[name] = session
        return self._sessions[name], self.instances[name].endpoint

    def list_instances(self) -> list[dict[str, str]]:
        """List all registered Graylog instances.

        Returns:
            List of dicts with ``name``, ``endpoint``, and ``default`` keys.
        """
        return [
            {
                "name": n,
                "endpoint": i.endpoint,
                "default": n == self.default_name,
            }
            for n, i in self.instances.items()
        ]

    # ------------------------------------------------------------------
    # HTTP plumbing
    # ------------------------------------------------------------------

    def _make_request(
        self,
        method: str,
        endpoint: str,
        params: dict[str, Any] | None = None,
        data: dict[str, Any] | None = None,
        instance: str | None = None,
    ) -> dict[str, Any]:
        """Make an HTTP request to a Graylog API.

        Args:
            method: HTTP method (GET, POST, PUT, DELETE).
            endpoint: API endpoint path (e.g., ``/api/streams``).
            params: Query parameters to include in the request URL.
            data: JSON body data to send with the request.
            instance: Target instance name, or ``None`` for the default.

        Returns:
            Parsed JSON response as a dictionary. Returns ``{}`` for
            204 No Content or empty responses.

        Raises:
            requests.exceptions.HTTPError: If the server returns an error.
            requests.exceptions.RequestException: If the request fails.
        """
        session, base_url = self._resolve(instance)
        url = urljoin(base_url, endpoint)
        timeout = self.instances[instance or self.default_name].timeout

        try:
            logger.debug("Making %s request to %s", method, url)
            if data:
                logger.debug("Request data: %s", data)
            if params:
                logger.debug("Request params: %s", params)

            response = session.request(
                method=method,
                url=url,
                params=params,
                json=data,
                timeout=timeout,
            )

            logger.debug("Response status: %s", response.status_code)

            # Handle authentication errors specifically
            if response.status_code == 401:
                logger.error("Authentication failed - check your token or username/password")
                raise requests.exceptions.HTTPError(
                    f"Authentication failed (401): {response.text}"
                )

            response.raise_for_status()

            # Handle 204 No Content and empty bodies
            if response.status_code == 204 or not response.text:
                return {}

            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error("Graylog API request failed: %s", e)
            if hasattr(e, "response") and e.response is not None:
                logger.error("Response status: %s", e.response.status_code)
                logger.error("Response text: %s", e.response.text)
            raise

    # ------------------------------------------------------------------
    # Time-range parsing
    # ------------------------------------------------------------------

    def _parse_time_range(self, time_range: str | None) -> dict[str, Any]:
        """Parse a time range string into Graylog API format.

        Graylog API expects relative time ranges in seconds for the
        ``/relative`` endpoint.  For absolute time ranges, it expects
        ISO 8601 format.

        Args:
            time_range: Relative time string (e.g., ``"1h"``, ``"7d"``) or
                ISO 8601 timestamp. ``None`` or empty string returns ``{}``.

        Returns:
            Dictionary with a ``"range"`` key containing seconds for relative
            ranges, or the original string for absolute/unrecognized formats.
            Returns ``{}`` when the input is falsy.
        """
        if not time_range:
            return {}

        # Supported units and their conversion to seconds
        units = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
        unit = time_range[-1]
        value = time_range[:-1]

        if unit in units and value.isdigit():
            seconds = int(value) * units[unit]
            return {"range": seconds}

        # Try ISO 8601 format
        try:
            datetime.fromisoformat(time_range.replace("Z", "+00:00"))
            return {"range": time_range}
        except ValueError:
            logger.warning("Unrecognized time range format: %s", time_range)
            return {"range": time_range}

    # ------------------------------------------------------------------
    # Search
    # ------------------------------------------------------------------

    def search_logs(
        self,
        params: QueryParams,
        instance: str | None = None,
    ) -> dict[str, Any]:
        """Search logs using the Graylog universal relative search API.

        Args:
            params: Query parameters including query string, time range,
                fields, limits, and sort options.
            instance: Target instance name, or ``None`` for the default.

        Returns:
            Dictionary containing ``messages``, ``total_results``,
            ``fields``, ``time``, and ``query`` keys.

        Raises:
            ValueError: If the query string is empty.
        """
        if not params.query:
            raise ValueError("Query parameter is required")

        search_params: dict[str, Any] = {
            "query": params.query,
            "limit": params.limit,
            "offset": params.offset,
        }

        if params.sort:
            search_params["sort"] = f"{params.sort}:{params.sort_direction}"

        time_range = params.time_range or "1h"
        time_range_parsed = self._parse_time_range(time_range)
        if time_range_parsed:
            search_params.update(time_range_parsed)

        if params.fields:
            search_params["fields"] = ",".join(params.fields)

        if params.stream_id:
            search_params["streams"] = [params.stream_id]

        if params.decorate is not None:
            search_params["decorate"] = params.decorate
        if params.filter is not None:
            search_params["filter"] = params.filter
        if params.highlight is not None:
            search_params["highlight"] = params.highlight

        search_params = {k: v for k, v in search_params.items() if v is not None}

        return self._make_request(
            "GET",
            "/api/search/universal/relative",
            params=search_params,
            instance=instance,
        )

    def get_log_statistics(
        self,
        query: str,
        time_range: str,
        aggregation: AggregationParams,
        instance: str | None = None,
    ) -> dict[str, Any]:
        """Get log statistics and aggregations.

        Args:
            query: Search query to filter logs before aggregation.
            time_range: Time range for analysis (e.g., ``"1h"``, ``"7d"``).
            aggregation: Aggregation parameters (type, field, size, interval).
            instance: Target instance name, or ``None`` for the default.

        Returns:
            Aggregation results from Graylog.

        Raises:
            ValueError: If query or aggregation field is empty, or the time
                range is invalid.
        """
        if not query:
            raise ValueError("Query parameter is required")
        if not aggregation.field:
            raise ValueError("Aggregation field is required")

        time_range_parsed = self._parse_time_range(time_range)
        if not time_range_parsed:
            raise ValueError("Valid time range is required")

        request_body: dict[str, Any] = {
            "query": query,
            "range": time_range_parsed["range"],
            "field": aggregation.field,
            "size": aggregation.size,
        }

        if aggregation.interval:
            request_body["interval"] = aggregation.interval

        request_body = {k: v for k, v in request_body.items() if v is not None}

        endpoint = f"/api/search/universal/relative/{aggregation.type}"
        return self._make_request("POST", endpoint, data=request_body, instance=instance)

    # ------------------------------------------------------------------
    # Streams
    # ------------------------------------------------------------------

    def list_streams(self, instance: str | None = None) -> list[dict[str, Any]]:
        """List all available streams.

        Args:
            instance: Target instance name, or ``None`` for the default.

        Returns:
            List of stream dictionaries.
        """
        response = self._make_request("GET", "/api/streams", instance=instance)
        return response.get("streams", [])

    def get_stream_info(
        self,
        stream_id: str,
        instance: str | None = None,
    ) -> dict[str, Any]:
        """Get detailed information about a stream.

        Args:
            stream_id: The unique identifier of the stream.
            instance: Target instance name, or ``None`` for the default.

        Returns:
            Dictionary with stream details.

        Raises:
            ValueError: If stream_id is empty.
        """
        if not stream_id:
            raise ValueError("Stream ID is required")
        return self._make_request("GET", f"/api/streams/{stream_id}", instance=instance)

    def search_stream_logs(
        self,
        stream_id: str,
        params: QueryParams,
        instance: str | None = None,
    ) -> dict[str, Any]:
        """Search logs within a specific stream.

        Args:
            stream_id: The stream to search in.
            params: Query parameters for the search.
            instance: Target instance name, or ``None`` for the default.

        Returns:
            Dictionary containing search results from the stream.

        Raises:
            ValueError: If stream_id is empty.
        """
        if not stream_id:
            raise ValueError("Stream ID is required")

        params.stream_id = stream_id

        if not params.query or params.query.strip() == "":
            params.query = "*"

        if params.limit < 1:
            params.limit = 1
        elif params.limit > 100:
            params.limit = 100

        return self.search_logs(params, instance=instance)

    # ------------------------------------------------------------------
    # System
    # ------------------------------------------------------------------

    def get_system_info(self, instance: str | None = None) -> dict[str, Any]:
        """Get Graylog system information.

        Args:
            instance: Target instance name, or ``None`` for the default.

        Returns:
            Dictionary with system info (version, hostname, cluster, etc.).
        """
        return self._make_request("GET", "/api/system", instance=instance)

    def test_connection(self, instance: str | None = None) -> bool:
        """Test connection to a Graylog instance.

        Args:
            instance: Target instance name, or ``None`` for the default.

        Returns:
            ``True`` if the connection and authentication succeed.
        """
        try:
            session, base_url = self._resolve(instance)
            timeout = self.instances[instance or self.default_name].timeout

            response = session.get(base_url, timeout=timeout)
            logger.debug("Basic connectivity test: %s", response.status_code)

            self.get_system_info(instance=instance)
            logger.info("Graylog connection successful")
            return True
        except requests.exceptions.HTTPError as e:
            if "401" in str(e):
                logger.error("Authentication failed - check your username and password")
            else:
                logger.error("HTTP error during connection test: %s", e)
            return False
        except requests.exceptions.ConnectionError as e:
            logger.error("Connection test failed: %s", e)
            return False
        except Exception as e:
            logger.error("Connection test failed: %s", e)
            return False

    # ------------------------------------------------------------------
    # Notifications
    # ------------------------------------------------------------------

    def get_notifications(
        self, instance: str | None = None
    ) -> list[dict[str, Any]]:
        """Get system notifications.

        Args:
            instance: Target instance name, or ``None`` for the default.

        Returns:
            List of notification dictionaries.
        """
        response = self._make_request(
            "GET", "/api/system/notifications", instance=instance
        )
        return response.get("notifications", [])

    def dismiss_notification(
        self,
        notification_type: str,
        instance: str | None = None,
    ) -> dict[str, Any]:
        """Dismiss a system notification.

        Args:
            notification_type: The notification type to dismiss.
            instance: Target instance name, or ``None`` for the default.

        Returns:
            Empty dict on success (HTTP 204).
        """
        return self._make_request(
            "DELETE",
            f"/api/system/notifications/{notification_type}",
            instance=instance,
        )

    # ------------------------------------------------------------------
    # Sidecars
    # ------------------------------------------------------------------

    def list_sidecars(
        self, instance: str | None = None
    ) -> list[dict[str, Any]]:
        """List all registered sidecars.

        Args:
            instance: Target instance name, or ``None`` for the default.

        Returns:
            List of sidecar dictionaries.
        """
        response = self._make_request("GET", "/api/sidecars", instance=instance)
        return response.get("sidecars", [])

    def get_sidecar(
        self,
        sidecar_id: str,
        instance: str | None = None,
    ) -> dict[str, Any]:
        """Get details of a specific sidecar.

        Args:
            sidecar_id: The sidecar node ID.
            instance: Target instance name, or ``None`` for the default.

        Returns:
            Dictionary with sidecar details.
        """
        return self._make_request(
            "GET", f"/api/sidecars/{sidecar_id}", instance=instance
        )

    def update_sidecar_tags(
        self,
        sidecar_id: str,
        tags: list[str],
        instance: str | None = None,
    ) -> dict[str, Any]:
        """Update tags on a sidecar.

        Args:
            sidecar_id: The sidecar node ID.
            tags: List of tag strings to set.
            instance: Target instance name, or ``None`` for the default.

        Returns:
            Response from the API.
        """
        return self._make_request(
            "PUT",
            f"/api/sidecars/{sidecar_id}/tags",
            data={"tags": tags},
            instance=instance,
        )

    def assign_sidecar_configurations(
        self,
        nodes: list[dict[str, Any]],
        instance: str | None = None,
    ) -> dict[str, Any]:
        """Assign configurations to sidecar nodes.

        Args:
            nodes: List of node assignment dicts (node_id + config).
            instance: Target instance name, or ``None`` for the default.

        Returns:
            Response from the API.
        """
        return self._make_request(
            "PUT",
            "/api/sidecars/configurations",
            data={"nodes": nodes},
            instance=instance,
        )

    def list_sidecar_configurations(
        self, instance: str | None = None
    ) -> list[dict[str, Any]]:
        """List all sidecar configurations.

        Args:
            instance: Target instance name, or ``None`` for the default.

        Returns:
            List of configuration dictionaries.
        """
        response = self._make_request(
            "GET", "/api/sidecar/configurations", instance=instance
        )
        return response.get("configurations", [])

    def get_sidecar_configuration(
        self,
        config_id: str,
        instance: str | None = None,
    ) -> dict[str, Any]:
        """Get a specific sidecar configuration.

        Args:
            config_id: The configuration ID.
            instance: Target instance name, or ``None`` for the default.

        Returns:
            Dictionary with configuration details.
        """
        return self._make_request(
            "GET", f"/api/sidecar/configurations/{config_id}", instance=instance
        )

    def list_collectors(
        self, instance: str | None = None
    ) -> list[dict[str, Any]]:
        """List all sidecar collectors.

        Args:
            instance: Target instance name, or ``None`` for the default.

        Returns:
            List of collector dictionaries.
        """
        response = self._make_request(
            "GET", "/api/sidecar/collectors", instance=instance
        )
        return response.get("collectors", [])

    def sidecar_action(
        self,
        sidecar_id: str,
        action: str,
        collector_id: str,
        instance: str | None = None,
    ) -> dict[str, Any]:
        """Perform an action on a sidecar collector.

        Args:
            sidecar_id: The sidecar node ID.
            action: Action to perform (e.g., ``"restart"``).
            collector_id: The collector to act on.
            instance: Target instance name, or ``None`` for the default.

        Returns:
            Response from the API.
        """
        return self._make_request(
            "PUT",
            f"/api/sidecars/{sidecar_id}/action",
            data={"action": action, "collector_id": collector_id},
            instance=instance,
        )

    def get_sidecars_administration(
        self, instance: str | None = None
    ) -> dict[str, Any]:
        """Get sidecar administration overview.

        Args:
            instance: Target instance name, or ``None`` for the default.

        Returns:
            Dictionary with sidecars admin data and pagination.
        """
        return self._make_request(
            "GET", "/api/sidecars/administration", instance=instance
        )
