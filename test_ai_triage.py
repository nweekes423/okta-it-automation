"""Tests for ai_triage.py with mocked API responses."""
import os
from unittest.mock import Mock, patch

import pytest
import requests

import ai_triage


OKTA_CSV = (
    "id,login,name,email,status,created,last_login,days_since_login,"
    "groups,mfa_factors,has_mfa,stale,stalled\n"
    "u1,stale@example.com,Stale User,s@x.com,ACTIVE,2024-01-01,2024-01-01,300,"
    "Users,,False,True,False\n"
    "u2,stuck@example.com,Stuck User,s2@x.com,PROVISIONED,2024-01-01,,300,"
    "Everyone,,False,False,True\n"
    "u3,fresh@example.com,Fresh User,f@x.com,ACTIVE,2024-01-01,2025-01-01,1,"
    "Users,tok:OKTA,True,False,False\n"
)

DEVICE_CSV = (
    "device_id,name,serial,platform,model,os_version,user,blueprint,"
    "mdm_enabled,agent_installed,filevault,last_check_in,days_since_checkin,flags\n"
    "d1,bob-mac,C02,Mac,MBP,13.0,bob@x.com,Eng,True,True,False,2025-01-01,300,"
    "filevault_off; os_below_floor; stale_checkin\n"
    "d2,alice-mac,C03,Mac,MBP,15.0,alice@x.com,Eng,True,True,True,2025-01-01,1,\n"
)


def write_csv(tmp_path, name, content):
    p = tmp_path / name
    p.write_text(content)
    return str(p)


class TestLoadCsv:
    def test_load(self, tmp_path):
        path = write_csv(tmp_path, "a.csv", OKTA_CSV)
        rows = ai_triage.load_csv(path)
        assert len(rows) == 3

    def test_missing_file(self, tmp_path):
        with pytest.raises(IOError):
            ai_triage.load_csv(str(tmp_path / "nope.csv"))


class TestDetectDataset:
    def test_okta(self):
        rows = ai_triage.load_csv.__wrapped__ if False else None
        dataset = ai_triage.detect_dataset(
            list(__import__("csv").DictReader(OKTA_CSV.splitlines())), "x")
        assert dataset == "okta_users"

    def test_devices(self):
        import csv as csvmod
        rows = list(csvmod.DictReader(DEVICE_CSV.splitlines()))
        assert ai_triage.detect_dataset(rows, "x") == "devices"


class TestFlaggedRows:
    def test_okta_flags_stale_stalled_no_mfa(self):
        import csv as csvmod
        rows = list(csvmod.DictReader(OKTA_CSV.splitlines()))
        flagged = ai_triage.flagged_rows(rows, "okta_users")
        logins = {r["login"] for r in flagged}
        assert logins == {"stale@example.com", "stuck@example.com"}

    def test_devices_flags_nonempty(self):
        import csv as csvmod
        rows = list(csvmod.DictReader(DEVICE_CSV.splitlines()))
        flagged = ai_triage.flagged_rows(rows, "devices")
        assert len(flagged) == 1
        assert flagged[0]["name"] == "bob-mac"


class TestBuildContext:
    def test_includes_counts_and_flagged(self, tmp_path):
        okta_path = write_csv(tmp_path, "okta.csv", OKTA_CSV)
        dev_path = write_csv(tmp_path, "dev.csv", DEVICE_CSV)
        inputs = []
        for path in (okta_path, dev_path):
            rows = ai_triage.load_csv(path)
            ds = ai_triage.detect_dataset(rows, path)
            inputs.append({"path": path, "dataset": ds, "rows": rows,
                           "flagged": ai_triage.flagged_rows(rows, ds)})
        ctx = ai_triage.build_context(inputs)
        assert "okta_users" in ctx
        assert "devices" in ctx
        assert "Stale ACTIVE accounts: 1" in ctx
        assert "filevault_off" in ctx
        assert "bob-mac" in ctx


class TestCallAnthropic:
    @patch("ai_triage.time.sleep")
    def test_success(self, mock_sleep):
        resp = Mock()
        resp.status_code = 200
        resp.json.return_value = {
            "content": [{"type": "text", "text": "Report body"}]
        }
        with patch("requests.post", return_value=resp):
            result = ai_triage.call_anthropic("prompt", "key", "model")
        assert result == "Report body"

    @patch("ai_triage.time.sleep")
    def test_rate_limit_retry(self, mock_sleep):
        limited = Mock()
        limited.status_code = 429
        limited.headers = {"Retry-After": "1"}
        ok = Mock()
        ok.status_code = 200
        ok.json.return_value = {"content": [{"type": "text", "text": "ok"}]}
        with patch("requests.post", side_effect=[limited, ok]):
            result = ai_triage.call_anthropic("prompt", "key", "model")
        assert result == "ok"

    @patch("ai_triage.time.sleep")
    def test_http_error_raises(self, mock_sleep):
        resp = Mock()
        resp.status_code = 401
        resp.raise_for_status.side_effect = requests.HTTPError("401")
        with patch("requests.post", return_value=resp):
            with pytest.raises(requests.HTTPError):
                ai_triage.call_anthropic("prompt", "bad", "model")


class TestMain:
    def test_demo_mode_no_key_needed(self, tmp_path):
        csv_path = write_csv(tmp_path, "okta.csv", OKTA_CSV)
        out = tmp_path / "report.md"
        with patch.dict(os.environ, {}, clear=True), \
             patch("sys.argv", ["ai_triage.py", "--input", csv_path,
                                "--demo", "--output", str(out)]):
            assert ai_triage.main() == 0
        assert "DEMO" in out.read_text()

    def test_missing_api_key(self, tmp_path):
        csv_path = write_csv(tmp_path, "okta.csv", OKTA_CSV)
        with patch.dict(os.environ, {}, clear=True), \
             patch("sys.argv", ["ai_triage.py", "--input", csv_path]):
            assert ai_triage.main() == 1

    @patch("ai_triage.call_anthropic", return_value="# Real report")
    def test_real_run(self, mock_call, tmp_path):
        csv_path = write_csv(tmp_path, "okta.csv", OKTA_CSV)
        out = tmp_path / "report.md"
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "k"}), \
             patch("sys.argv", ["ai_triage.py", "--input", csv_path,
                                "--output", str(out)]):
            assert ai_triage.main() == 0
        mock_call.assert_called_once()
        assert out.read_text() == "# Real report\n"
