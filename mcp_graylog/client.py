"""Graylog API client for MCP server."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import urljoin

import requests
from pydantic import BaseModel, Field

from .config import config

logger = logging.getLogger(__name__)


class TimeRange(BaseModel):
    """Time range for log queries.

    Attributes:
        type: Time range type (relative, absolute).
        from_: Start time (aliased as "from" in serialization).
        to: End time.
    """

    type: str = Field(..., description="Time range type (relative, absolute)")
    from_: str | None = Field(None, alias="from", description="Start time")
    to: str | None = Field(None, description="End time")


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
    """Client for interacting with the Graylog REST API.

    Handles authentication, request construction, and response parsing for
    all supported Graylog API endpoints including search, streams, and system info.

    Attributes:
        base_url: The base URL of the Graylog server (without trailing slash).
        session: Pre-configured requests session with auth and content headers.
        timeout: Request timeout in seconds.
    """

    def __init__(self) -> None:
        self.base_url = config.graylog.endpoint.rstrip("/")
        self.session = requests.Session()

        # Set up authentication headers
        auth_headers = config.auth_headers
        logger.debug(f"Setting up authentication headers: {list(auth_headers.keys())}")

        self.session.headers.update(auth_headers)
        self.session.headers.update(
            {"Content-Type": "application/json", "Accept": "application/json"}
        )

        self.session.verify = config.graylog.verify_ssl
        self.timeout = config.graylog.timeout

    def _make_request(
        self,
        method: str,
        endpoint: str,
        params: dict[str, Any] | None = None,
        data: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Make an HTTP request to the Graylog API.

        Args:
            method: HTTP method (GET, POST, PUT, DELETE).
            endpoint: API endpoint path (e.g., "/api/streams").
            params: Query parameters to include in the request URL.
            data: JSON body data to send with the request.

        Returns:
            Parsed JSON response as a dictionary.

        Raises:
            requests.exceptions.HTTPError: If the server returns an error status.
            requests.exceptions.RequestException: If the request fails.
        """
        url = urljoin(self.base_url, endpoint)

        try:
            logger.debug(f"Making {method} request to {url}")
            logger.debug(f"Headers: {dict(self.session.headers)}")
            if data:
                logger.debug(f"Request data: {data}")
            if params:
                logger.debug(f"Request params: {params}")

            response = self.session.request(
                method=method, url=url, params=params, json=data, timeout=self.timeout
            )

            logger.debug(f"Response status: {response.status_code}")
            logger.debug(f"Response headers: {dict(response.headers)}")

            # Handle authentication errors specifically
            if response.status_code == 401:
                logger.error("Authentication failed - check your token or username/password")
                logger.error(f"Response text: {response.text}")
                raise requests.exceptions.HTTPError(
                    f"Authentication failed (401): {response.text}"
                )

            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Graylog API request failed: {e}")
            if hasattr(e, "response") and e.response is not None:
                logger.error(f"Response status: {e.response.status_code}")
                logger.error(f"Response text: {e.response.text}")
            raise

    def _parse_time_range(self, time_range: str) -> dict[str, Any]:
        """Parse a time range string into Graylog API format.

        Graylog API expects relative time ranges in seconds for the /relative
        endpoint.  For absolute time ranges, it expects ISO 8601 format.

        Args:
            time_range: Relative time string (e.g., "1h", "7d") or ISO 8601 timestamp.

        Returns:
            Dictionary with a "range" key containing seconds (int) for relative
            ranges, or the original string for absolute/unrecognized formats.
            Returns an empty dict when the input is falsy.
        """
        if not time_range:
            return {}

        # Supported units and their conversion to seconds
        units = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
        unit = time_range[-1]
        value = time_range[:-1]

        if unit in units and value.isdigit():
            # Convert to seconds for Graylog API
            seconds = int(value) * units[unit]
            return {"range": seconds}

        # If not a recognized relative range, assume it's an absolute time range
        # Graylog expects ISO 8601 format for absolute ranges
        try:
            # Try to parse as ISO 8601 format
            datetime.fromisoformat(time_range.replace("Z", "+00:00"))
            return {"range": time_range}
        except ValueError:
            # If not ISO format, return as-is (Graylog will handle the error)
            logger.warning(f"Unrecognized time range format: {time_range}")
            return {"range": time_range}

    def search_logs(self, params: QueryParams) -> dict[str, Any]:
        """
        Search logs using Graylog API.

        PURPOSE: Execute log search queries against Graylog with flexible filtering, sorting, and pagination options.

        INPUT FORMAT: QueryParams object with the following structure:
        {
            "query": "level:ERROR AND source:nginx",  // REQUIRED: Elasticsearch query syntax
            "time_range": "1h",                       // OPTIONAL: Time range (1h, 24h, 7d, etc.)
            "fields": ["message", "level", "source"], // OPTIONAL: Specific fields to return
            "limit": 50,                              // OPTIONAL: Max results (default: 50)
            "offset": 0,                              // OPTIONAL: Pagination offset (default: 0)
            "sort": "timestamp",                      // OPTIONAL: Sort field
            "sort_direction": "desc",                 // OPTIONAL: Sort direction (asc/desc)
            "stream_id": "stream_123",                // OPTIONAL: Filter by specific stream
            "decorate": true,                         // OPTIONAL: Decorate messages (default: true)
            "filter": "additional_filter",            // OPTIONAL: Additional filter query
            "highlight": false                        // OPTIONAL: Enable result highlighting
        }

        GRAYLOG API ENDPOINT: /api/search/universal/relative (GET)

        OUTPUT: Dictionary containing search results with:
        - messages: Array of log messages with content and metadata
        - total_results: Total number of matching logs
        - fields: Available fields in the results
        - time: Query execution time information
        - query: The executed query string
        """
        # Validate required parameters
        if not params.query:
            raise ValueError("Query parameter is required")

        search_params = {
            "query": params.query,
            "limit": params.limit,
            "offset": params.offset,
        }

        # Add sort parameter if specified
        if params.sort:
            search_params["sort"] = f"{params.sort}:{params.sort_direction}"

        # Add time range - default to 1h if not specified
        time_range = params.time_range or "1h"
        time_range_parsed = self._parse_time_range(time_range)
        if time_range_parsed:
            search_params.update(time_range_parsed)

        # Add fields filter - Graylog expects comma-separated string
        if params.fields:
            search_params["fields"] = ",".join(params.fields)

        # Add stream filter - Graylog expects list of stream IDs
        if params.stream_id:
            search_params["streams"] = [params.stream_id]

        # Add advanced Graylog parameters if set
        if params.decorate is not None:
            search_params["decorate"] = params.decorate
        if params.filter is not None:
            search_params["filter"] = params.filter
        if params.highlight is not None:
            search_params["highlight"] = params.highlight

        # Remove None values
        search_params = {k: v for k, v in search_params.items() if v is not None}

        logger.debug(f"Search params: {search_params}")

        # Use GET and query parameters for this endpoint
        return self._make_request(
            "GET", "/api/search/universal/relative", params=search_params
        )

    def get_log_statistics(
        self, query: str, time_range: str, aggregation: AggregationParams
    ) -> dict[str, Any]:
        """
        Get log statistics and aggregations.

        PURPOSE: Analyze log data using various aggregation types to extract insights like top sources, error counts, time-based trends, and statistical summaries.

        INPUT FORMAT:
        - query: REQUIRED - Search query to filter logs before aggregation
        - time_range: REQUIRED - Time range for analysis (e.g., "1h", "24h", "7d")
        - aggregation: AggregationParams object with:
          {
            "type": "terms",           // REQUIRED: Aggregation type
            "field": "source",         // REQUIRED: Field to aggregate on
            "size": 10,                // OPTIONAL: Number of buckets (default: 10)
            "interval": "1h"           // OPTIONAL: Time interval for date_histogram
          }

        AGGREGATION TYPES SUPPORTED:
        - "terms": Count occurrences by field values (e.g., top sources, levels)
        - "date_histogram": Time-based grouping (requires interval parameter)
        - "cardinality": Count unique values in a field
        - "stats": Statistical summary (min, max, avg, sum)
        - "min", "max", "avg", "sum": Single statistical value

        GRAYLOG API ENDPOINT: /api/search/universal/relative/{aggregation_type} (POST)

        OUTPUT: Dictionary containing aggregation results with:
        - aggregation: Aggregation results with buckets and counts
        - query: The executed query string
        - time: Query execution time information
        - total_results: Total number of logs analyzed
        """
        # Validate required parameters
        if not query:
            raise ValueError("Query parameter is required")
        if not aggregation.field:
            raise ValueError("Aggregation field is required")

        # Parse time range
        time_range_parsed = self._parse_time_range(time_range)
        if not time_range_parsed:
            raise ValueError("Valid time range is required")

        # Build request body according to Graylog API specification
        request_body = {
            "query": query,
            "range": time_range_parsed["range"],
            "field": aggregation.field,
            "size": aggregation.size,
        }

        # Add interval for date histograms
        if aggregation.interval:
            request_body["interval"] = aggregation.interval

        # Remove None values
        request_body = {k: v for k, v in request_body.items() if v is not None}

        logger.debug(f"Aggregation request body: {request_body}")

        endpoint = f"/api/search/universal/relative/{aggregation.type}"
        return self._make_request("POST", endpoint, data=request_body)

    def list_streams(self) -> list[dict[str, Any]]:
        """
        List all available streams.

        PURPOSE: Retrieve a complete list of all log streams configured in Graylog with their metadata and configuration details.

        INPUT: No parameters required.

        GRAYLOG API ENDPOINT: /api/streams (GET)

        OUTPUT: List of dictionaries containing stream information:
        [
            {
                "id": "stream_id_123",
                "title": "nginx_access_logs",
                "description": "Nginx access logs from web servers",
                "disabled": false,
                "rules": [...],
                "created_at": "2024-01-01T00:00:00.000Z",
                "updated_at": "2024-01-01T00:00:00.000Z",
                "creator_user_id": "user_123",
                "outputs": [...],
                "stream_rules": [...]
            }
        ]
        """
        response = self._make_request("GET", "/api/streams")
        return response.get("streams", [])

    def get_stream_info(self, stream_id: str) -> dict[str, Any]:
        """
        Get detailed information about a stream.

        PURPOSE: Retrieve comprehensive details about a single stream including configuration, rules, outputs, and status information.

        INPUT:
        - stream_id: REQUIRED - The unique identifier of the stream (e.g., "5abb3f2f7bb9fd00011595fe")

        GRAYLOG API ENDPOINT: /api/streams/{stream_id} (GET)

        OUTPUT: Dictionary containing detailed stream information:
        {
            "id": "stream_id_123",
            "title": "nginx_access_logs",
            "description": "Nginx access logs from web servers",
            "disabled": false,
            "rules": [...],
            "outputs": [...],
            "stream_rules": [...],
            "created_at": "2024-01-01T00:00:00.000Z",
            "updated_at": "2024-01-01T00:00:00.000Z",
            "creator_user_id": "user_123",
            "matching_messages": 1500,
            "remove_matches_from_default_stream": false
        }
        """
        if not stream_id:
            raise ValueError("Stream ID is required")
        return self._make_request("GET", f"/api/streams/{stream_id}")

    def search_stream_logs(self, stream_id: str, params: QueryParams) -> dict[str, Any]:
        """
        Search logs within a specific stream.

        PURPOSE: Execute log search queries that are restricted to a specific stream, useful for analyzing logs from particular applications or services.

        INPUT FORMAT:
        - stream_id: REQUIRED - The ID of the stream to search in (e.g., "5abb3f2f7bb9fd00011595fe")
        - params: QueryParams object with search parameters (same as search_logs)

        BEHAVIOR:
        - Automatically filters results to the specified stream
        - Uses the same search capabilities as search_logs but scoped to one stream
        - If query is empty, defaults to "*" (all logs in stream)
        - Limits results to maximum of 100 logs per request

        GRAYLOG API ENDPOINT: /api/search/universal/relative (GET) with stream filter

        OUTPUT: Dictionary containing search results from the specified stream:
        {
            "messages": [...],
            "total_results": 150,
            "fields": [...],
            "time": {...},
            "query": "level:ERROR"
        }
        """
        # Validate stream_id
        if not stream_id:
            raise ValueError("Stream ID is required")

        # Ensure stream_id is set in params
        params.stream_id = stream_id

        # Validate query - if empty or None, use wildcard
        if not params.query or params.query.strip() == "":
            params.query = "*"

        # Ensure limit is within reasonable bounds
        if params.limit < 1:
            params.limit = 1
        elif params.limit > 100:
            params.limit = 100

        logger.debug(f"Searching stream {stream_id} with query: {params.query}")
        return self.search_logs(params)

    def get_system_info(self) -> dict[str, Any]:
        """
        Get Graylog system information.

        PURPOSE: Retrieve comprehensive system information about the Graylog instance including version, status, configuration, and resource usage.

        INPUT: No parameters required.

        GRAYLOG API ENDPOINT: /api/system (GET)

        OUTPUT: Dictionary containing system information:
        {
            "version": "5.2.0",
            "hostname": "graylog-server",
            "tagline": "Manage your logs in the dark and have multi-line JSON logs without tears.",
            "cluster_id": "cluster_123",
            "node_id": "node_123",
            "lifecycle": "running",
            "lb_status": "alive",
            "timezone": "UTC",
            "startup_time": "2024-01-01T00:00:00.000Z",
            "jvm": {...},
            "system": {...},
            "input": {...},
            "output": {...},
            "indices": {...}
        }
        """
        return self._make_request("GET", "/api/system")

    def test_connection(self) -> bool:
        """
        Test connection to Graylog server.

        PURPOSE: Verify connectivity and authentication to the Graylog server, useful for health checks and troubleshooting.

        INPUT: No parameters required.

        TEST PROCESS:
        1. Tests basic connectivity to the Graylog server
        2. Verifies authentication credentials
        3. Attempts to access system information endpoint

        OUTPUT: Boolean indicating connection status:
        - True: Successfully connected and authenticated
        - False: Connection failed (network, authentication, or server issues)

        ERROR HANDLING:
        - 401 errors: Authentication failure (check username/password)
        - Connection errors: Network connectivity issues
        - Other errors: Server availability or configuration issues
        """
        try:
            # First test basic connectivity
            response = self.session.get(self.base_url, timeout=self.timeout)
            logger.debug(f"Basic connectivity test: {response.status_code}")

            # Then test API authentication
            self.get_system_info()
            logger.info("Graylog connection successful")
            return True
        except requests.exceptions.HTTPError as e:
            if "401" in str(e):
                logger.error("Authentication failed - check your username and password")
                logger.error(
                    f"   Authorization header: {self.session.headers.get('Authorization', 'None')[:20]}..."
                )
            else:
                logger.error(f"HTTP error during connection test: {e}")
            return False
        except requests.exceptions.ConnectionError as e:
            # Handle connection errors more gracefully for mock endpoints
            if (
                "mock-graylog-server" in self.base_url
                or "graylog-server" in self.base_url
            ):
                logger.debug(f"Mock Graylog server not available: {e}")
                return False
            else:
                logger.error(f"Connection test failed: {e}")
                return False
        except Exception as e:
            # Handle other errors more gracefully for mock endpoints
            if (
                "mock-graylog-server" in self.base_url
                or "graylog-server" in self.base_url
            ):
                logger.debug(f"Mock Graylog server not available: {e}")
                return False
            else:
                logger.error(f"Connection test failed: {e}")
                return False
