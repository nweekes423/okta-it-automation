"""Tests for device_audit.py using mocked HTTP responses."""
import os
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock, patch

import pytest
import requests

import device_audit


def make_device(**overrides):
    device = {
        "device_id": "dev-001",
        "device_name": "test-mac",
        "serial_number": "C02XL0001",
        "platform": "Mac",
        "model": "MacBook Pro",
        "os_version": "15.1",
        "last_check_in": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "mdm_enabled": True,
        "agent_installed": True,
        "is_missing": False,
        "is_removed": False,
        "filevault_enabled": True,
        "blueprint_name": "Engineering",
        "user": {"email": "user@example.com"},
        "lost_mode_status": "",
    }
    device.update(overrides)
    return device


class TestValidateKandjiUrl:
    def test_valid_urls(self):
        assert device_audit.validate_kandji_url("https://acme.api.kandji.io")
        assert device_audit.validate_kandji_url("https://acme.api.eu.kandji.io/")
        assert device_audit.validate_kandji_url("https://acme.api.irunow.com")

    def test_invalid_urls(self):
        assert not device_audit.validate_kandji_url("http://acme.api.kandji.io")
        assert not device_audit.validate_kandji_url("https://evil.com")
        assert not device_audit.validate_kandji_url("not-a-url")


class TestPaginateDevices:
    def test_single_page(self):
        session = Mock()
        resp = Mock()
        resp.status_code = 200
        resp.json.return_value = [{"device_id": "1"}, {"device_id": "2"}]
        session.get.return_value = resp

        with patch.object(device_audit, "api_get", return_value=resp):
            result = device_audit.paginate_devices(session, "https://x.api.kandji.io")
        assert len(result) == 2

    def test_multiple_pages(self):
        page1 = [{"device_id": str(i)} for i in range(300)]
        page2 = [{"device_id": "last"}]
        resp1, resp2 = Mock(), Mock()
        resp1.json.return_value = page1
        resp2.json.return_value = page2

        with patch.object(device_audit, "api_get", side_effect=[resp1, resp2]):
            result = device_audit.paginate_devices(Mock(), "https://x.api.kandji.io")
        assert len(result) == 301


class TestGetFilevault:
    def test_non_mac_returns_none_without_api_call(self):
        session = Mock()
        result = device_audit.get_filevault(
            session, "https://x.api.kandji.io",
            {"platform": "iPhone", "device_id": "d1"}
        )
        assert result is None
        session.get.assert_not_called()

    def test_direct_field(self):
        result = device_audit.get_filevault(
            Mock(), "demo", {"platform": "Mac", "filevault_enabled": False}
        )
        assert result is False

    def test_details_fallback(self):
        session = Mock()
        resp = Mock()
        resp.json.return_value = {"security": {"filevault_enabled": True}}
        with patch.object(device_audit, "api_get", return_value=resp):
            result = device_audit.get_filevault(
                session, "https://x.api.kandji.io",
                {"platform": "Mac", "device_id": "d1"}
            )
        assert result is True

    def test_details_api_error_returns_none(self):
        session = Mock()
        with patch.object(device_audit, "api_get",
                          side_effect=requests.RequestException("boom")):
            result = device_audit.get_filevault(
                session, "https://x.api.kandji.io",
                {"platform": "Mac", "device_id": "d1"}
            )
        assert result is None


class TestAuditDevice:
    def test_compliant_mac_no_flags(self):
        row = device_audit.audit_device(
            Mock(), "demo", make_device(), stale_days=14, min_os=None
        )
        assert row["flags"] == ""
        assert row["filevault"] is True
        assert row["user"] == "user@example.com"

    def test_filevault_off_flagged(self):
        row = device_audit.audit_device(
            Mock(), "demo",
            make_device(filevault_enabled=False),
            stale_days=14, min_os=None
        )
        assert "filevault_off" in row["flags"]

    def test_iphone_no_filevault_flag(self):
        row = device_audit.audit_device(
            Mock(), "demo",
            make_device(platform="iPhone"),
            stale_days=14, min_os=None
        )
        assert "filevault_off" not in row["flags"]

    def test_stale_checkin_flagged(self):
        old = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
        row = device_audit.audit_device(
            Mock(), "demo", make_device(last_check_in=old),
            stale_days=14, min_os=None
        )
        assert "stale_checkin" in row["flags"]

    def test_never_checked_in_flagged(self):
        row = device_audit.audit_device(
            Mock(), "demo", make_device(last_check_in=None),
            stale_days=14, min_os=None
        )
        assert "stale_checkin" in row["flags"]

    def test_min_os_flagged(self):
        row = device_audit.audit_device(
            Mock(), "demo", make_device(os_version="13.6"),
            stale_days=14, min_os="14.0"
        )
        assert "os_below_floor" in row["flags"]

    def test_min_os_not_flagged_when_equal(self):
        row = device_audit.audit_device(
            Mock(), "demo", make_device(os_version="14.0"),
            stale_days=14, min_os="14.0"
        )
        assert "os_below_floor" not in row["flags"]

    def test_agent_and_mdm_flags(self):
        row = device_audit.audit_device(
            Mock(), "demo",
            make_device(mdm_enabled=False, agent_installed=False, is_missing=True),
            stale_days=14, min_os=None
        )
        assert "mdm_disabled" in row["flags"]
        assert "agent_missing" in row["flags"]
        assert "reported_missing" in row["flags"]

    def test_lost_mode_flagged(self):
        row = device_audit.audit_device(
            Mock(), "demo", make_device(lost_mode_status="Lost"),
            stale_days=14, min_os=None
        )
        assert "lost_mode" in row["flags"]

    def test_removed_device_returns_none(self):
        assert device_audit.audit_device(
            Mock(), "demo", make_device(is_removed=True),
            stale_days=14, min_os=None
        ) is None


class TestDemoMode:
    def test_demo_devices_have_expected_mix(self):
        devices = device_audit.demo_devices()
        assert len(devices) >= 5
        platforms = {d["platform"] for d in devices}
        assert "Mac" in platforms and "iPhone" in platforms

    def test_demo_run_end_to_end(self, tmp_path):
        out = tmp_path / "demo.csv"
        with patch("sys.argv", ["device_audit.py", "--demo",
                                "--output", str(out), "--min-os", "14.0"]):
            assert device_audit.main() == 0
        content = out.read_text()
        assert "filevault_off" in content
        assert "lost_mode" in content
        assert "os_below_floor" in content


class TestMain:
    def test_missing_env_vars(self):
        with patch.dict(os.environ, {}, clear=True), \
             patch("sys.argv", ["device_audit.py"]):
            assert device_audit.main() == 1

    def test_invalid_url(self):
        with patch.dict(os.environ, {
            "KANDJI_URL": "https://evil.com", "KANDJI_TOKEN": "tok"
        }), patch("sys.argv", ["device_audit.py"]):
            assert device_audit.main() == 1

    @patch("device_audit.paginate_devices")
    def test_successful_run(self, mock_paginate, tmp_path):
        mock_paginate.return_value = [make_device()]
        out = tmp_path / "devices.csv"
        with patch.dict(os.environ, {
            "KANDJI_URL": "https://acme.api.kandji.io", "KANDJI_TOKEN": "tok"
        }), patch("sys.argv", ["device_audit.py", "--output", str(out)]):
            assert device_audit.main() == 0
        assert "test-mac" in out.read_text()
