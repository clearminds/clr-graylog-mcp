"""MCP server for Graylog integration.

Exposes Graylog search, stream, aggregation, system, notification, and
sidecar tools via the Model Context Protocol (MCP) using FastMCP.
"""

from __future__ import annotations

import json
import logging
import sys
from typing import Any

from fastmcp import FastMCP
from pydantic import BaseModel, Field, field_validator

from .client import AggregationParams, GraylogClient, QueryParams
from .config import Settings
from .middleware import ToolValidationMiddleware

# ---------------------------------------------------------------------------
# FastMCP server
# ---------------------------------------------------------------------------

mcp_server = FastMCP("graylog")
mcp_server.add_middleware(ToolValidationMiddleware())

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Global state — initialised in main()
# ---------------------------------------------------------------------------

settings = Settings()
_client: GraylogClient | None = None

# Tools removed in read-only mode.
WRITE_TOOLS: list[str] = [
    "graylog_dismiss_notification",
    "graylog_update_sidecar_tags",
    "graylog_assign_sidecar_configurations",
    "graylog_sidecar_action",
]

# ---------------------------------------------------------------------------
# Pydantic request models
# ---------------------------------------------------------------------------


class SearchLogsRequest(BaseModel):
    """Request model for searching logs.

    Attributes:
        query: Elasticsearch-syntax search query.
        time_range: Relative or absolute time range string.
        fields: Specific fields to include in results.
        limit: Maximum number of results to return.
        offset: Pagination offset for results.
        sort: Field name to sort results by.
        sort_direction: Sort order, either "asc" or "desc".
        stream_id: Restrict search to a specific stream.
    """

    query: str = Field(..., description="Search query (Elasticsearch syntax)")
    time_range: str | None = Field(
        "1h",
        description="Time range (e.g., '1h', '24h', '7d'). Defaults to '1h' if not specified.",
    )
    fields: list[str] | None = Field(None, description="Fields to return")
    limit: int = Field(50, description="Maximum number of results")
    offset: int = Field(0, description="Result offset")
    sort: str | None = Field(None, description="Sort field")
    sort_direction: str = Field("desc", description="Sort direction (asc/desc)")
    stream_id: str | None = Field(None, description="Stream ID to search in")

    @field_validator("query")
    @classmethod
    def validate_query(cls, v: str) -> str:
        """Validate that query is not empty."""
        if not v or not v.strip():
            raise ValueError("Query cannot be empty")
        return v.strip()

    @field_validator("limit")
    @classmethod
    def validate_limit(cls, v: int) -> int:
        """Validate limit is within reasonable bounds."""
        if v < 1:
            raise ValueError("Limit must be at least 1")
        if v > 1000:
            raise ValueError("Limit cannot exceed 1000")
        return v

    @field_validator("time_range")
    @classmethod
    def validate_time_range(cls, v: str | None) -> str | None:
        """Validate time range format."""
        if v is None:
            return v

        import re

        relative_pattern = r"^\d+[smhdw]$"
        if re.match(relative_pattern, v):
            return v

        try:
            from datetime import datetime

            datetime.fromisoformat(v.replace("Z", "+00:00"))
            return v
        except ValueError:
            raise ValueError(
                f"Invalid time range format: {v}. Use relative (e.g., '1h') or ISO 8601 format"
            )


class AggregationRequest(BaseModel):
    """Request model for log aggregations.

    Attributes:
        query: Elasticsearch-syntax search query to filter logs before aggregation.
        time_range: Relative or absolute time range string.
        aggregation_type: Type of aggregation (e.g., "terms", "date_histogram").
        field: Field name to aggregate on.
        size: Number of aggregation buckets to return.
        interval: Time interval for date histogram aggregations.
    """

    query: str = Field(..., description="Search query")
    time_range: str = Field(
        "1h",
        description="Time range (e.g., '1h', '24h', '7d'). Defaults to '1h' if not specified.",
    )
    aggregation_type: str = Field(
        ..., description="Aggregation type (terms, date_histogram, etc.)"
    )
    field: str = Field(..., description="Field to aggregate on")
    size: int = Field(10, description="Number of buckets")
    interval: str | None = Field(
        None, description="Time interval for date histograms"
    )

    @field_validator("query")
    @classmethod
    def validate_query(cls, v: str) -> str:
        """Validate that query is not empty."""
        if not v or not v.strip():
            raise ValueError("Query cannot be empty")
        return v.strip()

    @field_validator("aggregation_type")
    @classmethod
    def validate_aggregation_type(cls, v: str) -> str:
        """Validate aggregation type."""
        valid_types = [
            "terms",
            "date_histogram",
            "cardinality",
            "stats",
            "min",
            "max",
            "avg",
            "sum",
        ]
        if v not in valid_types:
            raise ValueError(
                f"Invalid aggregation type: {v}. Valid types: {valid_types}"
            )
        return v

    @field_validator("field")
    @classmethod
    def validate_field(cls, v: str) -> str:
        """Validate that field is not empty."""
        if not v or not v.strip():
            raise ValueError("Field cannot be empty")
        return v.strip()

    @field_validator("size")
    @classmethod
    def validate_size(cls, v: int) -> int:
        """Validate size is within reasonable bounds."""
        if v < 1:
            raise ValueError("Size must be at least 1")
        if v > 100:
            raise ValueError("Size cannot exceed 100")
        return v

    @field_validator("time_range")
    @classmethod
    def validate_time_range(cls, v: str) -> str:
        """Validate time range format."""
        if not v or not v.strip():
            raise ValueError("Time range is required")

        import re

        relative_pattern = r"^\d+[smhdw]$"
        if re.match(relative_pattern, v):
            return v

        try:
            from datetime import datetime

            datetime.fromisoformat(v.replace("Z", "+00:00"))
            return v
        except ValueError:
            raise ValueError(
                f"Invalid time range format: {v}. Use relative (e.g., '1h') or ISO 8601 format"
            )


class StreamSearchRequest(BaseModel):
    """Request model for searching logs in a specific stream.

    Attributes:
        stream_id: Unique identifier of the Graylog stream to search.
        query: Elasticsearch-syntax search query.
        time_range: Relative or absolute time range string.
        fields: Specific fields to include in results.
        limit: Maximum number of results (1--100).
    """

    stream_id: str = Field(
        ..., description="Stream ID (e.g., '5abb3f2f7bb9fd00011595fe')"
    )
    query: str = Field(
        ...,
        description="Search query (e.g., '*' for all messages, 'level:ERROR' for errors)",
    )
    time_range: str | None = Field(
        "1h",
        description="Time range (e.g., '1h', '24h', '7d'). Defaults to '1h' if not specified.",
    )
    fields: list[str] | None = Field(
        None, description="Fields to return (e.g., ['message', 'level', 'source'])"
    )
    limit: int = Field(50, description="Maximum number of results (1-100)")

    @field_validator("stream_id")
    @classmethod
    def validate_stream_id(cls, v: str) -> str:
        """Validate that stream_id is not empty."""
        if not v or not v.strip():
            raise ValueError("Stream ID cannot be empty")
        return v.strip()

    @field_validator("query")
    @classmethod
    def validate_query(cls, v: str) -> str:
        """Validate that query is not empty."""
        if not v or not v.strip():
            raise ValueError("Query cannot be empty")
        return v.strip()

    @field_validator("limit")
    @classmethod
    def validate_limit(cls, v: int) -> int:
        """Validate limit is within reasonable bounds."""
        if v < 1:
            raise ValueError("Limit must be at least 1")
        if v > 100:
            raise ValueError("Limit cannot exceed 100")
        return v

    @field_validator("time_range")
    @classmethod
    def validate_time_range(cls, v: str | None) -> str | None:
        """Validate time range format."""
        if v is None:
            return v

        import re

        relative_pattern = r"^\d+[smhdw]$"
        if re.match(relative_pattern, v):
            return v

        try:
            from datetime import datetime

            datetime.fromisoformat(v.replace("Z", "+00:00"))
            return v
        except ValueError:
            raise ValueError(
                f"Invalid time range format: {v}. Use relative (e.g., '1h') or ISO 8601 format"
            )


# ---------------------------------------------------------------------------
# Instance tools
# ---------------------------------------------------------------------------


@mcp_server.tool()
def graylog_instances() -> str:
    """List all configured Graylog instances.

    Returns name, endpoint, and default flag for each instance.
    """
    result = _client.list_instances()
    return json.dumps({"items": result, "total": len(result)}, indent=2)


# ---------------------------------------------------------------------------
# Search tools
# ---------------------------------------------------------------------------


@mcp_server.tool()
def graylog_search_logs(request: SearchLogsRequest, instance: str | None = None) -> str:
    """Search logs in Graylog using Elasticsearch query syntax.

    Args:
        request: Search parameters including query, time_range, fields,
            limit, offset, sort, sort_direction, and stream_id.
        instance: Target Graylog instance name, or None for the default.
    """
    try:
        params = QueryParams(
            query=request.query,
            time_range=request.time_range,
            fields=request.fields,
            limit=request.limit,
            offset=request.offset,
            sort=request.sort,
            sort_direction=request.sort_direction,
            stream_id=request.stream_id,
        )

        result = _client.search_logs(params, instance=instance)
        return json.dumps(result, indent=2)

    except Exception as e:
        logger.error("graylog_search_logs failed: %s", e)
        return json.dumps({"error": str(e)}, indent=2)


@mcp_server.tool()
def graylog_get_log_statistics(
    request: AggregationRequest, instance: str | None = None
) -> str:
    """Get log statistics and aggregations from Graylog.

    Args:
        request: Aggregation parameters including query, time_range,
            aggregation_type, field, size, and interval.
        instance: Target Graylog instance name, or None for the default.
    """
    try:
        aggregation = AggregationParams(
            type=request.aggregation_type,
            field=request.field,
            size=request.size,
            interval=request.interval,
        )

        result = _client.get_log_statistics(
            query=request.query,
            time_range=request.time_range,
            aggregation=aggregation,
            instance=instance,
        )
        return json.dumps(result, indent=2)

    except Exception as e:
        logger.error("graylog_get_log_statistics failed: %s", e)
        return json.dumps({"error": str(e)}, indent=2)


# ---------------------------------------------------------------------------
# Stream tools
# ---------------------------------------------------------------------------


@mcp_server.tool()
def graylog_list_streams(instance: str | None = None) -> str:
    """List all available Graylog streams.

    Args:
        instance: Target Graylog instance name, or None for the default.
    """
    try:
        streams = _client.list_streams(instance=instance)
        return json.dumps(
            {"items": streams, "total": len(streams)}, indent=2
        )

    except Exception as e:
        logger.error("graylog_list_streams failed: %s", e)
        return json.dumps({"error": str(e)}, indent=2)


@mcp_server.tool()
def graylog_get_stream_info(
    stream_id: str, instance: str | None = None
) -> str:
    """Get detailed information about a specific Graylog stream.

    Args:
        stream_id: The unique identifier of the stream.
        instance: Target Graylog instance name, or None for the default.
    """
    try:
        stream_info = _client.get_stream_info(stream_id.strip(), instance=instance)
        return json.dumps(stream_info, indent=2)

    except Exception as e:
        logger.error("graylog_get_stream_info failed: %s", e)
        return json.dumps({"error": str(e)}, indent=2)


@mcp_server.tool()
def graylog_search_stream_logs(
    request: StreamSearchRequest, instance: str | None = None
) -> str:
    """Search logs within a specific Graylog stream.

    Args:
        request: Stream search parameters including stream_id, query,
            time_range, fields, and limit.
        instance: Target Graylog instance name, or None for the default.
    """
    try:
        params = QueryParams(
            query=request.query,
            time_range=request.time_range,
            fields=request.fields,
            limit=request.limit,
            stream_id=request.stream_id,
        )

        result = _client.search_stream_logs(
            request.stream_id, params, instance=instance
        )
        return json.dumps(result, indent=2)

    except Exception as e:
        logger.error("graylog_search_stream_logs failed: %s", e)
        return json.dumps({"error": str(e)}, indent=2)


@mcp_server.tool()
def graylog_search_streams_by_name(
    stream_name: str, instance: str | None = None
) -> str:
    """Search for Graylog streams by name or partial name.

    Case-insensitive partial matching on stream titles.

    Args:
        stream_name: Partial or full stream name to search for.
        instance: Target Graylog instance name, or None for the default.
    """
    try:
        all_streams = _client.list_streams(instance=instance)

        matching_streams = []
        search_term = stream_name.lower()

        for stream in all_streams:
            title = stream.get("title", "").lower()
            if search_term in title:
                matching_streams.append(
                    {
                        "id": stream.get("id"),
                        "title": stream.get("title"),
                        "description": stream.get("description"),
                        "disabled": stream.get("disabled", False),
                    }
                )

        return json.dumps(
            {
                "search_term": stream_name,
                "items": matching_streams,
                "total": len(matching_streams),
            },
            indent=2,
        )

    except Exception as e:
        logger.error("graylog_search_streams_by_name failed: %s", e)
        return json.dumps({"error": str(e)}, indent=2)


@mcp_server.tool()
def graylog_get_last_event_from_stream(
    stream_id: str,
    time_range: str = "1h",
    instance: str | None = None,
) -> str:
    """Get the last event from a specific Graylog stream.

    Args:
        stream_id: The ID of the stream to get the last event from.
        time_range: Time range to search in (default: "1h").
        instance: Target Graylog instance name, or None for the default.
    """
    try:
        params = QueryParams(
            query="*", time_range=time_range, limit=1, stream_id=stream_id
        )

        result = _client.search_stream_logs(
            stream_id, params, instance=instance
        )
        return json.dumps(result, indent=2)

    except Exception as e:
        logger.error("graylog_get_last_event_from_stream failed: %s", e)
        return json.dumps({"error": str(e)}, indent=2)


# ---------------------------------------------------------------------------
# System tools
# ---------------------------------------------------------------------------


@mcp_server.tool()
def graylog_get_system_info(instance: str | None = None) -> str:
    """Get Graylog system information and status.

    Args:
        instance: Target Graylog instance name, or None for the default.
    """
    try:
        system_info = _client.get_system_info(instance=instance)
        return json.dumps(system_info, indent=2)

    except Exception as e:
        logger.error("graylog_get_system_info failed: %s", e)
        return json.dumps({"error": str(e)}, indent=2)


@mcp_server.tool()
def graylog_test_connection(instance: str | None = None) -> str:
    """Test connection to a Graylog server.

    Args:
        instance: Target Graylog instance name, or None for the default.
    """
    try:
        name = instance or _client.default_name
        inst = _client.instances.get(name)
        endpoint = inst.endpoint if inst else "unknown"
        is_connected = _client.test_connection(instance=instance)
        return json.dumps(
            {"connected": is_connected, "instance": name, "endpoint": endpoint},
            indent=2,
        )

    except Exception as e:
        logger.error("graylog_test_connection failed: %s", e)
        name = instance or (_client.default_name if _client else "unknown")
        return json.dumps(
            {"connected": False, "instance": name, "error": str(e)},
            indent=2,
        )


# ---------------------------------------------------------------------------
# Convenience tools
# ---------------------------------------------------------------------------


@mcp_server.tool()
def graylog_get_error_logs(
    time_range: str = "1h",
    limit: int = 100,
    instance: str | None = None,
) -> str:
    """Get error logs from the last specified time range.

    Retrieves all error-level logs (ERROR, CRITICAL, FATAL).

    Args:
        time_range: Time range to search (default: "1h").
        limit: Maximum number of results (1-1000, default: 100).
        instance: Target Graylog instance name, or None for the default.
    """
    try:
        if limit < 1 or limit > 1000:
            return json.dumps(
                {"error": "Limit must be between 1 and 1000"}, indent=2
            )

        params = QueryParams(
            query="level:ERROR OR level:CRITICAL OR level:FATAL",
            time_range=time_range,
            limit=limit,
            fields=["message", "level", "source", "timestamp"],
        )

        result = _client.search_logs(params, instance=instance)
        return json.dumps(result, indent=2)

    except Exception as e:
        logger.error("graylog_get_error_logs failed: %s", e)
        return json.dumps({"error": str(e)}, indent=2)


@mcp_server.tool()
def graylog_get_log_count_by_level(
    time_range: str = "1h", instance: str | None = None
) -> str:
    """Get log count aggregated by log level.

    Args:
        time_range: Time range to analyse (default: "1h").
        instance: Target Graylog instance name, or None for the default.
    """
    try:
        aggregation = AggregationParams(type="terms", field="level", size=10)

        result = _client.get_log_statistics(
            query="*",
            time_range=time_range,
            aggregation=aggregation,
            instance=instance,
        )
        return json.dumps(result, indent=2)

    except Exception as e:
        logger.error("graylog_get_log_count_by_level failed: %s", e)
        return json.dumps({"error": str(e)}, indent=2)


# ---------------------------------------------------------------------------
# Notification tools
# ---------------------------------------------------------------------------


@mcp_server.tool()
def graylog_get_notifications(instance: str | None = None) -> str:
    """Get system notifications from Graylog.

    Args:
        instance: Target Graylog instance name, or None for the default.
    """
    try:
        notifications = _client.get_notifications(instance=instance)
        return json.dumps(
            {"items": notifications, "total": len(notifications)}, indent=2
        )

    except Exception as e:
        logger.error("graylog_get_notifications failed: %s", e)
        return json.dumps({"error": str(e)}, indent=2)


@mcp_server.tool()
def graylog_dismiss_notification(
    notification_type: str, instance: str | None = None
) -> str:
    """Dismiss a system notification.

    Args:
        notification_type: The notification type to dismiss.
        instance: Target Graylog instance name, or None for the default.
    """
    try:
        _client.dismiss_notification(
            notification_type, instance=instance
        )
        return json.dumps(
            {"dismissed": True, "notification_type": notification_type}, indent=2
        )

    except Exception as e:
        logger.error("graylog_dismiss_notification failed: %s", e)
        return json.dumps({"error": str(e)}, indent=2)


# ---------------------------------------------------------------------------
# Sidecar tools
# ---------------------------------------------------------------------------


@mcp_server.tool()
def graylog_list_sidecars(instance: str | None = None) -> str:
    """List all registered Graylog sidecars.

    Args:
        instance: Target Graylog instance name, or None for the default.
    """
    try:
        sidecars = _client.list_sidecars(instance=instance)
        return json.dumps(
            {"items": sidecars, "total": len(sidecars)}, indent=2
        )

    except Exception as e:
        logger.error("graylog_list_sidecars failed: %s", e)
        return json.dumps({"error": str(e)}, indent=2)


@mcp_server.tool()
def graylog_get_sidecar(
    sidecar_id: str, instance: str | None = None
) -> str:
    """Get details of a specific Graylog sidecar.

    Args:
        sidecar_id: The sidecar node ID.
        instance: Target Graylog instance name, or None for the default.
    """
    try:
        result = _client.get_sidecar(sidecar_id, instance=instance)
        return json.dumps(result, indent=2)

    except Exception as e:
        logger.error("graylog_get_sidecar failed: %s", e)
        return json.dumps({"error": str(e)}, indent=2)


@mcp_server.tool()
def graylog_update_sidecar_tags(
    sidecar_id: str,
    tags: list[str],
    instance: str | None = None,
) -> str:
    """Update tags on a Graylog sidecar.

    Args:
        sidecar_id: The sidecar node ID.
        tags: List of tag strings to set.
        instance: Target Graylog instance name, or None for the default.
    """
    try:
        result = _client.update_sidecar_tags(
            sidecar_id, tags, instance=instance
        )
        return json.dumps(result, indent=2)

    except Exception as e:
        logger.error("graylog_update_sidecar_tags failed: %s", e)
        return json.dumps({"error": str(e)}, indent=2)


@mcp_server.tool()
def graylog_assign_sidecar_configurations(
    nodes: list[dict[str, Any]],
    instance: str | None = None,
) -> str:
    """Assign configurations to sidecar nodes.

    Args:
        nodes: List of node assignment dicts (node_id + config).
        instance: Target Graylog instance name, or None for the default.
    """
    try:
        result = _client.assign_sidecar_configurations(
            nodes, instance=instance
        )
        return json.dumps(result, indent=2)

    except Exception as e:
        logger.error("graylog_assign_sidecar_configurations failed: %s", e)
        return json.dumps({"error": str(e)}, indent=2)


@mcp_server.tool()
def graylog_list_sidecar_configurations(
    instance: str | None = None,
) -> str:
    """List all sidecar configurations.

    Args:
        instance: Target Graylog instance name, or None for the default.
    """
    try:
        configs = _client.list_sidecar_configurations(instance=instance)
        return json.dumps(
            {"items": configs, "total": len(configs)}, indent=2
        )

    except Exception as e:
        logger.error("graylog_list_sidecar_configurations failed: %s", e)
        return json.dumps({"error": str(e)}, indent=2)


@mcp_server.tool()
def graylog_get_sidecar_configuration(
    configuration_id: str, instance: str | None = None
) -> str:
    """Get a specific sidecar configuration.

    Args:
        configuration_id: The configuration ID.
        instance: Target Graylog instance name, or None for the default.
    """
    try:
        result = _client.get_sidecar_configuration(
            configuration_id, instance=instance
        )
        return json.dumps(result, indent=2)

    except Exception as e:
        logger.error("graylog_get_sidecar_configuration failed: %s", e)
        return json.dumps({"error": str(e)}, indent=2)


@mcp_server.tool()
def graylog_list_collectors(instance: str | None = None) -> str:
    """List all sidecar collectors.

    Args:
        instance: Target Graylog instance name, or None for the default.
    """
    try:
        collectors = _client.list_collectors(instance=instance)
        return json.dumps(
            {"items": collectors, "total": len(collectors)}, indent=2
        )

    except Exception as e:
        logger.error("graylog_list_collectors failed: %s", e)
        return json.dumps({"error": str(e)}, indent=2)


@mcp_server.tool()
def graylog_sidecar_action(
    sidecar_id: str,
    action: str,
    collector_id: str,
    instance: str | None = None,
) -> str:
    """Perform an action on a sidecar collector (e.g., restart, stop).

    Args:
        sidecar_id: The sidecar node ID.
        action: Action to perform (e.g., "restart", "stop").
        collector_id: The collector to act on.
        instance: Target Graylog instance name, or None for the default.
    """
    try:
        result = _client.sidecar_action(
            sidecar_id, action, collector_id, instance=instance
        )
        return json.dumps(result, indent=2)

    except Exception as e:
        logger.error("graylog_sidecar_action failed: %s", e)
        return json.dumps({"error": str(e)}, indent=2)


@mcp_server.tool()
def graylog_sidecars_administration(instance: str | None = None) -> str:
    """Get sidecar administration overview.

    Args:
        instance: Target Graylog instance name, or None for the default.
    """
    try:
        result = _client.get_sidecars_administration(instance=instance)
        return json.dumps(result, indent=2)

    except Exception as e:
        logger.error("graylog_sidecars_administration failed: %s", e)
        return json.dumps({"error": str(e)}, indent=2)


# ---------------------------------------------------------------------------
# Composite init
# ---------------------------------------------------------------------------


def init_composite() -> FastMCP:
    """Initialize for composite mounting. Returns the FastMCP instance."""
    global _client

    instances = settings.load_instances()
    default_name = settings.get_default_name()

    _client = GraylogClient(instances, default_name)

    if settings.graylog_read_only and WRITE_TOOLS:
        for name in WRITE_TOOLS:
            mcp_server.remove_tool(name)

    return mcp_server


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Entry point for the MCP server."""
    global _client

    import argparse

    parser = argparse.ArgumentParser(description="Graylog MCP Server")
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse"],
        default="stdio",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
    )
    parser.add_argument(
        "--read-only",
        action="store_true",
        default=None,
        help="Run in read-only mode (hide write tools)",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        stream=sys.stderr,
    )

    # Load instances
    instances = settings.load_instances()
    if not instances:
        logger.error(
            "No Graylog instances configured. Set GRAYLOG_TOKEN or "
            "GRAYLOG_USERNAME/GRAYLOG_PASSWORD env vars, "
            "or create ~/.config/graylog/credentials.json"
        )
        sys.exit(1)

    default_name = settings.get_default_name()
    _client = GraylogClient(instances, default_name)

    for name, inst in instances.items():
        marker = " (default)" if name == default_name else ""
        logger.info("Graylog instance '%s'%s: %s", name, marker, inst.endpoint)

    # Read-only mode: remove write tools
    read_only = args.read_only if args.read_only is not None else settings.graylog_read_only
    if read_only and WRITE_TOOLS:
        for name in WRITE_TOOLS:
            mcp_server.remove_tool(name)
        logger.info("Read-only mode: %d write tools removed", len(WRITE_TOOLS))

    mcp_server.run(transport=args.transport)


if __name__ == "__main__":
    main()
