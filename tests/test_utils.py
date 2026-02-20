"""Tests for the utility functions module."""

import pytest
from datetime import datetime, timedelta

from mcp_graylog.utils import (
    parse_time_range,
    build_elasticsearch_query,
    extract_log_level,
    format_log_entry,
    validate_query_syntax,
    get_common_log_fields,
    parse_graylog_response,
)


class TestParseTimeRange:
    """Test cases for parse_time_range function."""

    def test_parse_time_range_hours(self) -> None:
        """Test parsing time range with hours."""
        result = parse_time_range("2h")

        assert "from" in result
        assert "to" in result
        assert isinstance(result["from"], datetime)
        assert isinstance(result["to"], datetime)
        assert result["to"] > result["from"]

    def test_parse_time_range_days(self) -> None:
        """Test parsing time range with days."""
        result = parse_time_range("3d")

        assert "from" in result
        assert "to" in result
        assert isinstance(result["from"], datetime)
        assert isinstance(result["to"], datetime)

    def test_parse_time_range_weeks(self) -> None:
        """Test parsing time range with weeks."""
        result = parse_time_range("1w")

        assert "from" in result
        assert "to" in result
        assert isinstance(result["from"], datetime)
        assert isinstance(result["to"], datetime)

    def test_parse_time_range_minutes(self) -> None:
        """Test parsing time range with minutes."""
        result = parse_time_range("30m")

        assert "from" in result
        assert "to" in result
        assert isinstance(result["from"], datetime)
        assert isinstance(result["to"], datetime)

    def test_parse_time_range_empty(self) -> None:
        """Test parsing empty time range."""
        result = parse_time_range("")
        assert result == {}

    def test_parse_time_range_none(self) -> None:
        """Test parsing None time range."""
        result = parse_time_range(None)
        assert result == {}

    def test_parse_time_range_invalid(self) -> None:
        """Test parsing invalid time range."""
        result = parse_time_range("invalid")
        assert result == {}


class TestBuildElasticsearchQuery:
    """Test cases for build_elasticsearch_query function."""

    def test_build_query_no_filters(self) -> None:
        """Test building query without filters."""
        result = build_elasticsearch_query("*", {})
        assert result == "*"

    def test_build_query_with_simple_filters(self) -> None:
        """Test building query with simple filters."""
        filters = {"level": "ERROR", "source": "web-server"}
        result = build_elasticsearch_query("*", filters)
        assert "level:ERROR" in result
        assert "source:web-server" in result
        assert " AND " in result

    def test_build_query_with_spaces_in_value(self) -> None:
        """Test building query with spaces in filter values."""
        filters = {"message": "error occurred"}
        result = build_elasticsearch_query("*", filters)
        assert 'message:"error occurred"' in result

    def test_build_query_with_base_query(self) -> None:
        """Test building query with existing base query."""
        filters = {"level": "ERROR"}
        result = build_elasticsearch_query("source:web-server", filters)
        assert "(source:web-server) AND (level:ERROR)" in result


class TestExtractLogLevel:
    """Test cases for extract_log_level function."""

    def test_extract_error_level(self) -> None:
        """Test extracting ERROR level."""
        message = "This is an ERROR message"
        result = extract_log_level(message)
        assert result == "ERROR"

    def test_extract_critical_level(self) -> None:
        """Test extracting CRITICAL level."""
        message = "CRITICAL system failure"
        result = extract_log_level(message)
        assert result == "CRITICAL"

    def test_extract_warning_level(self) -> None:
        """Test extracting WARNING level."""
        message = "WARNING: disk space low"
        result = extract_log_level(message)
        assert result == "WARNING"

    def test_extract_info_level(self) -> None:
        """Test extracting INFO level."""
        message = "INFO: user logged in"
        result = extract_log_level(message)
        assert result == "INFO"

    def test_extract_debug_level(self) -> None:
        """Test extracting DEBUG level."""
        message = "DEBUG: processing request"
        result = extract_log_level(message)
        assert result == "DEBUG"

    def test_extract_no_level(self) -> None:
        """Test extracting no level from message."""
        message = "This is a regular message"
        result = extract_log_level(message)
        assert result is None

    def test_extract_case_insensitive(self) -> None:
        """Test extracting level case insensitive."""
        message = "This is an error message"
        result = extract_log_level(message)
        assert result == "ERROR"


class TestFormatLogEntry:
    """Test cases for format_log_entry function."""

    def test_format_log_entry_basic(self) -> None:
        """Test formatting basic log entry."""
        log_entry = {
            "timestamp": "2023-01-01T12:00:00Z",
            "message": "Test message",
            "source": "test-source",
        }

        result = format_log_entry(log_entry)

        assert result["timestamp"] == "2023-01-01T12:00:00Z"
        assert result["message"] == "Test message"
        assert result["source"] == "test-source"
        assert "raw" in result

    def test_format_log_entry_with_level(self) -> None:
        """Test formatting log entry with level."""
        log_entry = {
            "timestamp": "2023-01-01T12:00:00Z",
            "message": "ERROR: Test error",
            "source": "test-source",
            "level": "ERROR",
        }

        result = format_log_entry(log_entry)

        assert result["level"] == "ERROR"

    def test_format_log_entry_extract_level(self) -> None:
        """Test formatting log entry with level extraction."""
        log_entry = {
            "timestamp": "2023-01-01T12:00:00Z",
            "message": "ERROR: Test error",
            "source": "test-source",
        }

        result = format_log_entry(log_entry)

        assert result["level"] == "ERROR"

    def test_format_log_entry_additional_fields(self) -> None:
        """Test formatting log entry with additional fields."""
        log_entry = {
            "timestamp": "2023-01-01T12:00:00Z",
            "message": "Test message",
            "source": "test-source",
            "host": "test-host",
            "process_id": "12345",
        }

        result = format_log_entry(log_entry)

        assert result["host"] == "test-host"
        assert result["process_id"] == "12345"


class TestValidateQuerySyntax:
    """Test cases for validate_query_syntax function."""

    def test_validate_empty_query(self) -> None:
        """Test validating empty query."""
        result = validate_query_syntax("")
        assert result is False

    def test_validate_none_query(self) -> None:
        """Test validating None query."""
        result = validate_query_syntax(None)
        assert result is False

    def test_validate_simple_query(self) -> None:
        """Test validating simple query."""
        result = validate_query_syntax("test")
        assert result is True

    def test_validate_query_with_quotes(self) -> None:
        """Test validating query with quotes."""
        result = validate_query_syntax('message:"test message"')
        assert result is True

    def test_validate_query_with_parentheses(self) -> None:
        """Test validating query with parentheses."""
        result = validate_query_syntax("(level:ERROR) AND (source:web)")
        assert result is True

    def test_validate_query_unbalanced_parentheses(self) -> None:
        """Test validating query with unbalanced parentheses."""
        result = validate_query_syntax("(level:ERROR AND source:web")
        assert result is False

    def test_validate_query_unbalanced_quotes(self) -> None:
        """Test validating query with unbalanced quotes."""
        result = validate_query_syntax('message:"test message')
        assert result is False


class TestGetCommonLogFields:
    """Test cases for get_common_log_fields function."""

    def test_get_common_log_fields(self) -> None:
        """Test getting common log fields."""
        fields = get_common_log_fields()

        assert "timestamp" in fields
        assert "message" in fields
        assert "source" in fields
        assert "level" in fields
        assert "host" in fields
        assert isinstance(fields, list)


class TestParseGraylogResponse:
    """Test cases for parse_graylog_response function."""

    def test_parse_graylog_response_basic(self) -> None:
        """Test parsing basic Graylog response."""
        response = {
            "total_results": 10,
            "execution_time": 0.5,
            "query": "test query",
            "timerange": {"from": "2023-01-01", "to": "2023-01-02"},
            "fields": ["message", "level"],
            "messages": [
                {
                    "message": {
                        "timestamp": "2023-01-01T12:00:00Z",
                        "message": "Test message",
                        "source": "test-source",
                    }
                }
            ],
        }

        result = parse_graylog_response(response)

        assert result["total_results"] == 10
        assert result["execution_time"] == 0.5
        assert result["metadata"]["query"] == "test query"
        assert len(result["messages"]) == 1
        assert result["messages"][0]["message"] == "Test message"

    def test_parse_graylog_response_empty(self) -> None:
        """Test parsing empty Graylog response."""
        response = {"total_results": 0, "execution_time": 0.1, "messages": []}

        result = parse_graylog_response(response)

        assert result["total_results"] == 0
        assert len(result["messages"]) == 0
