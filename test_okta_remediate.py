"""Tests for okta_remediate.py using mocked HTTP responses."""
import os
from unittest.mock import Mock, patch

import pytest
import requests

import okta_remediate


def make_row(**overrides):
    row = {
        "id": "user123",
        "login": "stale@example.com",
        "name": "Stale User",
        "email": "stale@example.com",
        "status": "ACTIVE",
        "created": "2024-01-01T00:00:00.000Z",
        "last_login": "2024-06-01T00:00:00.000Z",
        "days_since_login": 120,
        "groups": "Users",
        "mfa_factors": "token:software:totp:OKTA",
        "has_mfa": "True",
        "stale": "True",
    }
    row.update(overrides)
    return row


class TestLoadAuditCsv:
    """Test loading the audit CSV."""

    def test_load_valid_csv(self, tmp_path):
        csv_path = tmp_path / "audit.csv"
        csv_path.write_text(
            "id,login,name,status,stale\n"
            "u1,a@example.com,A User,ACTIVE,True\n"
        )
        rows = okta_remediate.load_audit_csv(str(csv_path))
        assert len(rows) == 1
        assert rows[0]["login"] == "a@example.com"

    def test_missing_columns(self, tmp_path):
        csv_path = tmp_path / "audit.csv"
        csv_path.write_text("login,name\na@example.com,A\n")
        with pytest.raises(ValueError, match="missing required columns"):
            okta_remediate.load_audit_csv(str(csv_path))

    def test_missing_file(self, tmp_path):
        with pytest.raises(IOError):
            okta_remediate.load_audit_csv(str(tmp_path / "nope.csv"))


class TestSelectTargets:
    """Test stale-account selection and safety exclusions."""

    def test_selects_stale_active_only(self):
        rows = [
            make_row(login="stale@example.com"),
            make_row(id="u2", login="fresh@example.com", stale="False"),
            make_row(id="u3", login="old@example.com", status="DEPROVISIONED"),
        ]
        targets = okta_remediate.select_targets(rows)
        assert [t["login"] for t in targets] == ["stale@example.com"]

    def test_exclude_substrings(self):
        rows = [
            make_row(login="admin@example.com"),
            make_row(id="u2", login="svc-backup@example.com"),
            make_row(id="u3", login="person@example.com"),
        ]
        targets = okta_remediate.select_targets(rows, exclude=["admin", "svc-"])
        assert [t["login"] for t in targets] == ["person@example.com"]

    def test_only_filter(self):
        rows = [
            make_row(login="a@example.com"),
            make_row(id="u2", login="b@example.com"),
        ]
        targets = okta_remediate.select_targets(rows, only=["b@example.com"])
        assert [t["login"] for t in targets] == ["b@example.com"]


class TestRemediateUser:
    """Test the remediation API call sequence."""

    def _mock_ok(self):
        session = Mock()
        resp = Mock()
        resp.status_code = 200
        resp.raise_for_status = Mock()
        session.request.return_value = resp
        return session

    def test_revoke_then_deactivate(self):
        session = self._mock_ok()
        with patch.object(okta_remediate, "user_factor_ids", return_value=[]):
            result = okta_remediate.remediate_user(
                session, "https://test.okta.com", "user123", remove_factors=True
            )

        assert result["error"] is None
        assert result["actions"] == ["sessions_revoked", "deactivated"]

        calls = session.request.call_args_list
        assert calls[0][0][0] == "DELETE"
        assert calls[0][0][1].endswith("/users/user123/sessions")
        assert calls[1][0][0] == "POST"
        assert calls[1][0][1].endswith("/users/user123/lifecycle/deactivate")

    def test_remove_factors(self):
        session = self._mock_ok()
        with patch.object(okta_remediate, "user_factor_ids", return_value=["f1", "f2"]):
            result = okta_remediate.remediate_user(
                session, "https://test.okta.com", "user123", remove_factors=True
            )

        assert "factor_removed" in result["actions"]
        factor_calls = [c for c in session.request.call_args_list
                        if "/factors/" in c[0][1]]
        assert len(factor_calls) == 2

    def test_no_factor_removal_by_default(self):
        session = self._mock_ok()
        with patch.object(okta_remediate, "user_factor_ids") as mock_factors:
            result = okta_remediate.remediate_user(
                session, "https://test.okta.com", "user123", remove_factors=False
            )
        mock_factors.assert_not_called()
        assert "factor_removed" not in result["actions"]

    def test_session_revoke_failure_aborts(self):
        session = Mock()
        resp = Mock()
        resp.status_code = 403
        resp.raise_for_status.side_effect = requests.HTTPError(response=resp)
        session.request.return_value = resp

        result = okta_remediate.remediate_user(
            session, "https://test.okta.com", "user123"
        )
        assert result["error"] is not None
        # Must not proceed to deactivate when session revoke fails
        methods = [c[0][0] for c in session.request.call_args_list]
        assert "POST" not in methods

    def test_deactivate_failure_recorded(self):
        session = self._mock_ok()
        call_count = {"n": 0}

        def side_effect(method, url, **kwargs):
            call_count["n"] += 1
            resp = Mock()
            resp.status_code = 200
            resp.raise_for_status = Mock()
            if "deactivate" in url:
                resp.raise_for_status.side_effect = requests.HTTPError("boom")
            return resp

        session.request.side_effect = side_effect
        result = okta_remediate.remediate_user(
            session, "https://test.okta.com", "user123"
        )
        assert result["error"] is not None
        assert "sessions_revoked" in result["actions"]


class TestUserFactorIds:
    """Test factor ID fetching."""

    def test_returns_active_ids(self):
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {"id": "f1", "factorType": "token:software:totp", "status": "ACTIVE"},
            {"id": "f2", "factorType": "push", "status": "INACTIVE"},
        ]
        mock_response.links = {}
        mock_session.get.return_value = mock_response

        result = okta_remediate.user_factor_ids(
            mock_session, "https://test.okta.com", "user123"
        )
        assert result == ["f1"]


class TestMain:
    """Test CLI behavior, especially the dry-run safety default."""

    def _env(self):
        return {
            "OKTA_ORG_URL": "https://test.okta.com",
            "OKTA_API_TOKEN": "test_token",
        }

    def _write_csv(self, tmp_path):
        csv_path = tmp_path / "audit.csv"
        csv_path.write_text(
            "id,login,name,email,status,created,last_login,days_since_login,"
            "groups,mfa_factors,has_mfa,stale\n"
            "u1,stale@example.com,Stale User,stale@example.com,ACTIVE,"
            "2024-01-01,2024-06-01,120,Users,,False,True\n"
        )
        return str(csv_path)

    @patch('sys.argv', ['okta_remediate.py', '--input', 'x.csv'])
    def test_missing_env_vars(self):
        with patch.dict(os.environ, {}, clear=True):
            assert okta_remediate.main() == 1

    def test_dry_run_makes_no_changes(self, tmp_path):
        csv_path = self._write_csv(tmp_path)
        with patch.dict(os.environ, self._env()), \
             patch('sys.argv', ['okta_remediate.py', '--input', csv_path]), \
             patch('okta_remediate.make_session') as mock_session:
            assert okta_remediate.main() == 0
            mock_session.assert_not_called()

    def test_execute_calls_remediation(self, tmp_path):
        csv_path = self._write_csv(tmp_path)
        mock_session = Mock()
        with patch.dict(os.environ, self._env()), \
             patch('sys.argv', ['okta_remediate.py', '--input', csv_path,
                                '--execute', '--output', str(tmp_path / 'r.csv')]), \
             patch('okta_remediate.make_session', return_value=mock_session), \
             patch('okta_remediate.remediate_user',
                   return_value={"actions": ["sessions_revoked", "deactivated"],
                                 "error": None}) as mock_rem:
            assert okta_remediate.main() == 0
            mock_rem.assert_called_once()
            assert (tmp_path / 'r.csv').exists()

    def test_exclude_results_in_no_targets(self, tmp_path):
        csv_path = self._write_csv(tmp_path)
        with patch.dict(os.environ, self._env()), \
             patch('sys.argv', ['okta_remediate.py', '--input', csv_path,
                                '--execute', '--exclude', 'stale']), \
             patch('okta_remediate.make_session') as mock_session:
            assert okta_remediate.main() == 0
            mock_session.assert_not_called()
