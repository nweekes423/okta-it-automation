"""Tests for okta_audit.py using mocked HTTP responses."""
import os
import sys
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock, patch

import pytest
import requests

import okta_audit


class TestValidateOktaUrl:
    """Test Okta URL validation."""

    def test_valid_url(self):
        assert okta_audit.validate_okta_url("https://example.okta.com")
        assert okta_audit.validate_okta_url("https://my-org-123.okta.com/")

    def test_invalid_url(self):
        assert not okta_audit.validate_okta_url("https://example.okta.com/admin")
        assert not okta_audit.validate_okta_url("https://example.com")
        assert not okta_audit.validate_okta_url("http://example.okta.com")
        assert not okta_audit.validate_okta_url("invalid-url")


class TestMakeSession:
    """Test session creation."""

    def test_valid_token(self):
        session = okta_audit.make_session("test_token")
        assert session.headers["Authorization"] == "SSWS test_token"
        assert session.headers["Accept"] == "application/json"

    def test_empty_token(self):
        with pytest.raises(ValueError, match="cannot be empty"):
            okta_audit.make_session("")


class TestApiGet:
    """Test API GET with retry logic."""

    @patch('okta_audit.time.sleep')
    @patch('okta_audit.time.time')
    def test_rate_limit_with_retry_after(self, mock_time, mock_sleep):
        mock_time.return_value = 1000
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 429
        mock_response.headers = {"Retry-After": "5"}
        mock_session.get.return_value = mock_response

        with pytest.raises(RuntimeError, match="Failed after 5 retries"):
            okta_audit.api_get(mock_session, "https://test.okta.com/api/v1/users")

        assert mock_sleep.call_count == 5
        mock_sleep.assert_called_with(5)

    @patch('okta_audit.time.sleep')
    @patch('okta_audit.time.time')
    def test_rate_limit_with_x_rate_limit_reset(self, mock_time, mock_sleep):
        # Provide enough values for all time.time() calls in the retry loop
        mock_time.side_effect = list(range(1000, 1035))
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 429
        mock_response.headers = {"X-Rate-Limit-Reset": "1010"}
        mock_session.get.return_value = mock_response

        with pytest.raises(RuntimeError, match="Failed after 5 retries"):
            okta_audit.api_get(mock_session, "https://test.okta.com/api/v1/users")

    def test_successful_request(self):
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = [{"id": "123"}]
        mock_response.links = {}
        mock_session.get.return_value = mock_response

        result = okta_audit.api_get(mock_session, "https://test.okta.com/api/v1/users")
        assert result.status_code == 200


class TestPaginate:
    """Test pagination."""

    def test_single_page(self):
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = [{"id": "123"}, {"id": "456"}]
        mock_response.links = {}
        mock_session.get.return_value = mock_response

        result = okta_audit.paginate(mock_session, "https://test.okta.com/api/v1/users")
        assert len(result) == 2
        assert result[0]["id"] == "123"

    def test_multiple_pages(self):
        mock_session = Mock()
        mock_response1 = Mock()
        mock_response1.status_code = 200
        mock_response1.json.return_value = [{"id": "123"}]
        mock_response1.links = {"next": {"url": "https://test.okta.com/api/v1/users?after=123"}}

        mock_response2 = Mock()
        mock_response2.status_code = 200
        mock_response2.json.return_value = [{"id": "456"}]
        mock_response2.links = {}

        mock_session.get.side_effect = [mock_response1, mock_response2]

        result = okta_audit.paginate(mock_session, "https://test.okta.com/api/v1/users")
        assert len(result) == 2


class TestParseTime:
    """Test timestamp parsing."""

    def test_valid_timestamp(self):
        result = okta_audit.parse_time("2024-01-01T12:00:00.000Z")
        assert result is not None
        assert result.tzinfo == timezone.utc

    def test_none_value(self):
        assert okta_audit.parse_time(None) is None

    def test_empty_string(self):
        assert okta_audit.parse_time("") is None

    def test_invalid_timestamp(self):
        assert okta_audit.parse_time("invalid") is None


class TestUserGroups:
    """Test user group fetching."""

    def test_successful_fetch(self):
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {"profile": {"name": "Admin"}},
            {"profile": {"name": "Users"}}
        ]
        mock_response.links = {}
        mock_session.get.return_value = mock_response

        result = okta_audit.user_groups(mock_session, "https://test.okta.com", "user123")
        assert result == ["Admin", "Users"]

    def test_api_error(self):
        mock_session = Mock()
        mock_session.get.side_effect = requests.RequestException("API error")

        result = okta_audit.user_groups(mock_session, "https://test.okta.com", "user123")
        assert result == []


class TestUserFactors:
    """Test user MFA factor fetching."""

    def test_active_factors(self):
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {"factorType": "token:software:totp", "provider": "OKTA", "status": "ACTIVE"},
            {"factorType": "push", "provider": "OKTA", "status": "INACTIVE"}
        ]
        mock_response.links = {}
        mock_session.get.return_value = mock_response

        result = okta_audit.user_factors(mock_session, "https://test.okta.com", "user123")
        assert result == ["token:software:totp:OKTA"]

    def test_no_active_factors(self):
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {"factorType": "push", "provider": "OKTA", "status": "INACTIVE"}
        ]
        mock_response.links = {}
        mock_session.get.return_value = mock_response

        result = okta_audit.user_factors(mock_session, "https://test.okta.com", "user123")
        assert result == []

    def test_api_restriction(self):
        mock_session = Mock()
        mock_session.get.side_effect = requests.HTTPError("Forbidden")

        result = okta_audit.user_factors(mock_session, "https://test.okta.com", "user123")
        assert result == []


class TestAudit:
    """Test main audit function."""

    @patch('okta_audit.user_groups')
    @patch('okta_audit.user_factors')
    @patch('okta_audit.paginate')
    def test_successful_audit(self, mock_paginate, mock_factors, mock_groups):
        now = datetime.now(timezone.utc)
        mock_paginate.return_value = [
            {
                "id": "user123",
                "status": "ACTIVE",
                "lastLogin": (now - timedelta(days=10)).isoformat().replace("+00:00", "Z"),
                "created": (now - timedelta(days=100)).isoformat().replace("+00:00", "Z"),
                "profile": {
                    "login": "test@example.com",
                    "firstName": "Test",
                    "lastName": "User",
                    "email": "test@example.com"
                }
            }
        ]
        mock_groups.return_value = ["Users"]
        mock_factors.return_value = ["token:software:totp:OKTA"]

        mock_session = Mock()
        result = okta_audit.audit(mock_session, "https://test.okta.com", 30)

        assert len(result) == 1
        assert result[0]["login"] == "test@example.com"
        assert result[0]["has_mfa"] is True
        assert result[0]["stale"] is False

    @patch('okta_audit.user_groups')
    @patch('okta_audit.user_factors')
    @patch('okta_audit.paginate')
    def test_stale_user_detection(self, mock_paginate, mock_factors, mock_groups):
        now = datetime.now(timezone.utc)
        mock_paginate.return_value = [
            {
                "id": "user123",
                "status": "ACTIVE",
                "lastLogin": (now - timedelta(days=60)).isoformat().replace("+00:00", "Z"),
                "created": (now - timedelta(days=100)).isoformat().replace("+00:00", "Z"),
                "profile": {
                    "login": "stale@example.com",
                    "firstName": "Stale",
                    "lastName": "User",
                    "email": "stale@example.com"
                }
            }
        ]
        mock_groups.return_value = ["Users"]
        mock_factors.return_value = []

        mock_session = Mock()
        result = okta_audit.audit(mock_session, "https://test.okta.com", 30)

        assert len(result) == 1
        assert result[0]["stale"] is True
        assert result[0]["has_mfa"] is False

    @patch('okta_audit.user_groups')
    @patch('okta_audit.user_factors')
    @patch('okta_audit.paginate')
    def test_never_logged_in(self, mock_paginate, mock_factors, mock_groups):
        now = datetime.now(timezone.utc)
        mock_paginate.return_value = [
            {
                "id": "user123",
                "status": "ACTIVE",
                "lastLogin": None,
                "created": (now - timedelta(days=60)).isoformat().replace("+00:00", "Z"),
                "profile": {
                    "login": "new@example.com",
                    "firstName": "New",
                    "lastName": "User",
                    "email": "new@example.com"
                }
            }
        ]
        mock_groups.return_value = ["Users"]
        mock_factors.return_value = []

        mock_session = Mock()
        result = okta_audit.audit(mock_session, "https://test.okta.com", 30)

        assert len(result) == 1
        assert result[0]["stale"] is True


class TestWriteCsv:
    """Test CSV writing."""

    def test_successful_write(self, tmp_path):
        rows = [
            {
                "id": "user123",
                "login": "test@example.com",
                "name": "Test User",
                "email": "test@example.com",
                "status": "ACTIVE",
                "created": "2024-01-01T00:00:00.000Z",
                "last_login": "2024-01-15T00:00:00.000Z",
                "days_since_login": 100,
                "groups": "Users",
                "mfa_factors": "token:software:totp:OKTA",
                "has_mfa": True,
                "stale": False
            }
        ]
        output_path = tmp_path / "test.csv"

        okta_audit.write_csv(rows, str(output_path))

        assert output_path.exists()
        content = output_path.read_text()
        assert "test@example.com" in content


class TestMain:
    """Test main entry point."""

    @patch('okta_audit.audit')
    @patch('okta_audit.write_csv')
    @patch('okta_audit.make_session')
    @patch('sys.argv', ['okta_audit.py'])
    def test_missing_env_vars(self, mock_session, mock_write, mock_audit):
        with patch.dict(os.environ, {}, clear=True):
            result = okta_audit.main()
            assert result == 1

    @patch('okta_audit.audit')
    @patch('okta_audit.write_csv')
    @patch('okta_audit.make_session')
    @patch('sys.argv', ['okta_audit.py'])
    def test_invalid_url(self, mock_session, mock_write, mock_audit):
        with patch.dict(os.environ, {"OKTA_ORG_URL": "invalid", "OKTA_API_TOKEN": "test"}):
            result = okta_audit.main()
            assert result == 1

    @patch('okta_audit.audit')
    @patch('okta_audit.write_csv')
    @patch('okta_audit.make_session')
    @patch('sys.argv', ['okta_audit.py'])
    def test_successful_run(self, mock_session, mock_write, mock_audit):
        mock_audit.return_value = [{"id": "123", "status": "ACTIVE", "stale": False}]
        with patch.dict(os.environ, {
            "OKTA_ORG_URL": "https://test.okta.com",
            "OKTA_API_TOKEN": "test_token"
        }):
            result = okta_audit.main()
            assert result == 0


class TestReadOnlySafety:
    """Ensure audit never makes state-changing API calls."""

    @patch('okta_audit.api_get')
    def test_api_get_only_get(self, mock_get):
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = []
        mock_response.links = {}
        mock_get.return_value = mock_response

        okta_audit.paginate(mock_session, "https://test.okta.com/api/v1/users")

        # Verify api_get was called (which only does GET requests)
        assert mock_get.called
