#!/usr/bin/env python3
"""Iru (formerly Kandji) device compliance audit.

Pulls the device inventory from the Kandji/Iru MDM API and flags endpoints
that need attention: missing agent/MDM enrollment, FileVault disabled,
OS below a floor, devices that stopped checking in, and devices in Lost
Mode. Read-only: it never changes anything in Kandji.

This is the endpoint counterpart to okta_audit.py — same audit -> CSV ->
flag pattern, different system of record.

WHAT YOU NEED TO PROVIDE (never commit real values):

  1. KANDJI_URL   - your API base URL, e.g.
                    https://yourcompany.api.kandji.io
                    (US tenants) or https://yourcompany.api.eu.kandji.io
                    (EU tenants). Create an API token in Kandji/Iru under
                    Settings > Access > API Token with read-only
                    "device list" permission — least privilege.
  2. KANDJI_TOKEN - the API token (shown once at creation).

  Where to set them:
    - On your Mac: export KANDJI_URL=... ; export KANDJI_TOKEN=...
    - In GitHub Actions: repo Settings > Secrets > Actions.

Usage:
    python device_audit.py --stale-days 14 --min-os 14.0 --output devices.csv
    python device_audit.py --demo --output devices_demo.csv   # no credentials
"""
import argparse
import csv
import logging
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import requests

from okta_audit import api_get, parse_time

TIMEOUT = 30
PAGE_SIZE = 300

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger(__name__)


# Check that KANDJI_URL looks like a real Kandji/Iru API host (https + kandji/iru in the domain).
def validate_kandji_url(url: str) -> bool:
    """Validate Kandji/Iru API base URL format."""
    url = url.rstrip("/")
    if not url.startswith("https://"):
        return False
    host = url[len("https://"):].split("/")[0]
    return "kandji" in host or "iru" in host


# Build a requests session that authenticates with a Bearer token, like a browser already logged in.
def make_session(token: str) -> requests.Session:
    """Create an authenticated requests session (Bearer token)."""
    if not token:
        raise ValueError("KANDJI_TOKEN cannot be empty")
    s = requests.Session()
    s.headers.update({"Authorization": f"Bearer {token}", "Accept": "application/json"})
    return s


# Page through GET /api/v1/devices until every enrolled device has been fetched.
def paginate_devices(session: requests.Session, base: str) -> List[Dict]:
    """Fetch all devices via offset pagination (300 per page)."""
    devices = []
    offset = 0
    while True:
        # Kandji caps pages at 300; we keep fetching until a short/empty
        # page signals the end of the inventory.
        resp = api_get(session, f"{base}/api/v1/devices",
                       {"limit": PAGE_SIZE, "offset": offset})
        page = resp.json()
        if not isinstance(page, list) or not page:
            break
        devices.extend(page)
        if len(page) < PAGE_SIZE:
            break
        offset += PAGE_SIZE
    return devices


# Recursively hunt through nested JSON for the first key whose name contains a substring (used to locate FileVault in varying API shapes).
def _find_key(obj: Any, needle: str) -> Any:
    """Recursively search a JSON structure for a key containing `needle`."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if needle in k.lower():
                return v
            found = _find_key(v, needle)
            if found is not None:
                return found
    elif isinstance(obj, list):
        for item in obj:
            found = _find_key(item, needle)
            if found is not None:
                return found
    return None


# Determine whether FileVault disk encryption is on for a device; returns True/False, or None when unknown or not a Mac.
def get_filevault(session: requests.Session, base: str, device: Dict) -> Optional[bool]:
    """Return FileVault state for a Mac, or None if unknown/not applicable.

    Checks the device payload first (demo data and some API versions include
    it), then falls back to the per-device details endpoint. FileVault is
    macOS-only, so non-Mac platforms return None without an API call.
    """
    platform = str(device.get("platform", "")).lower()
    # FileVault is a macOS-only feature — Kandji doesn't report it for
    # iPhone/iPad/Apple TV, so we skip the API call entirely for those.
    if platform and "mac" not in platform:
        return None
    direct = device.get("filevault_enabled")
    if direct is not None:
        return bool(direct)
    device_id = device.get("device_id")
    if not device_id:
        return None
    try:
        # The details endpoint nests FileVault under security settings and
        # the exact key varies by API version, so we search recursively.
        resp = api_get(session, f"{base}/api/v1/devices/{device_id}/details")
        raw = _find_key(resp.json(), "filevault")
        if raw is None:
            return None
        if isinstance(raw, dict):
            # Some API versions return {"filevault": {"enabled": true}}
            # or {"status": "ENABLED"} rather than a bare boolean.
            for k in ("enabled", "status", "value"):
                if k in raw:
                    raw = raw[k]
                    break
        if isinstance(raw, str):
            # Accept common truthy spellings; anything else is False-ish
            # but we still return the parsed bool.
            return raw.strip().upper() in ("TRUE", "ENABLED", "ON", "1", "YES")
        return bool(raw)
    except requests.RequestException as e:
        logger.warning(f"Could not fetch details for device {device_id}: {e}")
        return None


# Turn "14.4.1" into (14, 4, 1) so OS versions can be compared numerically.
def parse_os_version(version: str) -> Optional[tuple]:
    """Parse '14.4.1' into a comparable tuple of ints."""
    parts = re.findall(r"\d+", version or "")
    return tuple(int(p) for p in parts[:3]) if parts else None


# Evaluate a single device and return its CSV row with any compliance flags; returns None for removed devices.
def audit_device(
    session: requests.Session,
    base: str,
    device: Dict,
    stale_days: int,
    min_os: Optional[str],
) -> Optional[Dict[str, Any]]:
    """Evaluate one device and return a CSV row, or None if removed."""
    if device.get("is_removed"):
        return None

    now = datetime.now(timezone.utc)
    last_check_in = parse_time(device.get("last_check_in"))
    days_since = (now - last_check_in).days if last_check_in else ""
    filevault = get_filevault(session, base, device)
    min_os_tuple = parse_os_version(min_os) if min_os else None
    os_tuple = parse_os_version(str(device.get("os_version", "")))

    flags = []
    # Each flag maps to a distinct finding type so the report can be
    # grouped by cause: enrollment gaps, encryption, patch level,
    # connectivity, and physical-device state.
    if not device.get("mdm_enabled", True):
        flags.append("mdm_disabled")
    if not device.get("agent_installed", True):
        flags.append("agent_missing")
    if device.get("is_missing"):
        flags.append("reported_missing")
    if filevault is False:
        flags.append("filevault_off")
    if min_os_tuple and os_tuple and os_tuple < min_os_tuple:
        flags.append("os_below_floor")
    # A device that never checked in OR hasn't checked in within the
    # threshold is stale — likely retired, lost, or offline.
    if last_check_in is None or (
            isinstance(days_since, int) and days_since > stale_days):
        flags.append("stale_checkin")
    if device.get("lost_mode_status"):
        flags.append("lost_mode")

    user = device.get("user") or {}
    return {
        "device_id": device.get("device_id", ""),
        "name": device.get("device_name", ""),
        "serial": device.get("serial_number", ""),
        "platform": device.get("platform", ""),
        "model": device.get("model", ""),
        "os_version": device.get("os_version", ""),
        "user": user.get("email") or user.get("name", "") if isinstance(user, dict) else "",
        "blueprint": device.get("blueprint_name", ""),
        "mdm_enabled": device.get("mdm_enabled", ""),
        "agent_installed": device.get("agent_installed", ""),
        "filevault": filevault if filevault is not None else "",
        "last_check_in": device.get("last_check_in") or "",
        "days_since_checkin": days_since,
        "flags": "; ".join(flags),
    }


# Fake but realistic device inventory so the script can be demoed without a Kandji tenant.
def demo_devices() -> List[Dict]:
    """Synthetic device inventory for --demo runs and tests."""
    now = datetime.now(timezone.utc)
    recent = (now - timedelta(days=1)).isoformat().replace("+00:00", "Z")
    old = (now - timedelta(days=45)).isoformat().replace("+00:00", "Z")
    never = None
    return [
        {
            "device_id": "demo-001", "device_name": "alice-mbp", "serial_number": "C02XL0001",
            "platform": "Mac", "model": "MacBook Pro (14-inch, 2023)", "os_version": "15.1",
            "last_check_in": recent, "mdm_enabled": True, "agent_installed": True,
            "is_missing": False, "is_removed": False, "filevault_enabled": True,
            "blueprint_name": "Engineering", "user": {"email": "alice@example.com"},
            "lost_mode_status": "",
        },
        {
            "device_id": "demo-002", "device_name": "bob-mbp", "serial_number": "C02XL0002",
            "platform": "Mac", "model": "MacBook Pro (13-inch, 2022)", "os_version": "13.6",
            "last_check_in": old, "mdm_enabled": True, "agent_installed": True,
            "is_missing": False, "is_removed": False, "filevault_enabled": False,
            "blueprint_name": "Sales", "user": {"email": "bob@example.com"},
            "lost_mode_status": "",
        },
        {
            "device_id": "demo-003", "device_name": "carol-iphone", "serial_number": "F2LXK0003",
            "platform": "iPhone", "model": "iPhone 15", "os_version": "17.5",
            "last_check_in": recent, "mdm_enabled": True, "agent_installed": True,
            "is_missing": False, "is_removed": False,
            "blueprint_name": "Default", "user": {"email": "carol@example.com"},
            "lost_mode_status": "Lost",
        },
        {
            "device_id": "demo-004", "device_name": "dave-ipad", "serial_number": "DMPXA0004",
            "platform": "iPad", "model": "iPad Pro 11-inch", "os_version": "17.5",
            "last_check_in": never, "mdm_enabled": False, "agent_installed": False,
            "is_missing": True, "is_removed": False,
            "blueprint_name": "Default", "user": {"email": "dave@example.com"},
            "lost_mode_status": "",
        },
        {
            "device_id": "demo-005", "device_name": "erin-mac-mini", "serial_number": "C07XL0005",
            "platform": "Mac", "model": "Mac mini (M2)", "os_version": "14.2",
            "last_check_in": recent, "mdm_enabled": True, "agent_installed": True,
            "is_missing": False, "is_removed": False, "filevault_enabled": True,
            "blueprint_name": "IT", "user": {},
            "lost_mode_status": "",
        },
        {
            "device_id": "demo-006", "device_name": "frank-old-mbp", "serial_number": "C02XL0006",
            "platform": "Mac", "model": "MacBook Air (M1, 2020)", "os_version": "12.7",
            "last_check_in": old, "mdm_enabled": True, "agent_installed": True,
            "is_missing": False, "is_removed": False, "filevault_enabled": True,
            "blueprint_name": "Support", "user": {"email": "frank@example.com"},
            "lost_mode_status": "",
        },
        {
            "device_id": "demo-007", "device_name": "retired-mbp", "serial_number": "C02XL0007",
            "platform": "Mac", "model": "MacBook Pro (16-inch, 2019)", "os_version": "12.6",
            "last_check_in": old, "mdm_enabled": True, "agent_installed": True,
            "is_missing": False, "is_removed": True, "filevault_enabled": True,
            "blueprint_name": "Support", "user": {"email": "gone@example.com"},
            "lost_mode_status": "",
        },
    ]


# Write the audit rows to a CSV file with a stable column order.
def write_csv(rows: List[Dict[str, Any]], path: str) -> None:
    """Write audit results to CSV file."""
    if not rows:
        logger.error("No devices returned from audit")
        raise ValueError("Audit returned no devices")
    fieldnames = [
        "device_id", "name", "serial", "platform", "model", "os_version",
        "user", "blueprint", "mdm_enabled", "agent_installed", "filevault",
        "last_check_in", "days_since_checkin", "flags"
    ]
    try:
        with open(path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(rows)
        logger.info(f"Wrote {len(rows)} rows to {path}")
    except (IOError, csv.Error) as e:
        logger.error(f"Failed to write CSV: {e}")
        raise


# Print headline counts: total devices, flagged, noncompliant, stale check-ins.
def summarize(rows: List[Dict[str, Any]], stale_days: int) -> None:
    """Print audit summary."""
    flagged = [r for r in rows if r.get("flags")]
    noncompliant = [r for r in flagged
                    if any(f in r["flags"] for f in
                           ("mdm_disabled", "agent_missing", "filevault_off",
                            "os_below_floor", "reported_missing"))]
    logger.info(f"Devices: {len(rows)}  Flagged: {len(flagged)}")
    logger.info(f"Noncompliant: {len(noncompliant)}")
    logger.info(f"Stale check-in (>{stale_days} days or never): "
                f"{sum(1 for r in rows if 'stale_checkin' in r.get('flags', ''))}")


# CLI entry point: parse args, load devices (real API or --demo), audit, write CSV.
def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Read-only Iru/Kandji device compliance audit to CSV."
    )
    parser.add_argument("--output", default="device_audit.csv",
                        help="Output CSV file path")
    parser.add_argument("--stale-days", type=int, default=14,
                        help="Days without MDM check-in to flag a device")
    parser.add_argument("--min-os", default=None,
                        help="Minimum acceptable OS version, e.g. 14.0")
    parser.add_argument("--demo", action="store_true",
                        help="Run against built-in synthetic device data")
    parser.add_argument("--verbose", action="store_true",
                        help="Enable verbose logging")
    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    if args.demo:
        # Demo mode needs no session or base URL — audit_device only uses
        # them for the FileVault details fallback, which demo data
        # bypasses via the filevault_enabled field.
        session, base = None, "demo"
        devices = demo_devices()
        logger.info(f"DEMO MODE: auditing {len(devices)} synthetic devices")
    else:
        base = os.environ.get("KANDJI_URL", "").rstrip("/")
        token = os.environ.get("KANDJI_TOKEN", "")
        if not base:
            logger.error("KANDJI_URL environment variable not set")
            return 1
        if not token:
            logger.error("KANDJI_TOKEN environment variable not set")
            return 1
        if not validate_kandji_url(base):
            logger.error(f"Invalid KANDJI_URL format: {base}")
            return 1
        session = make_session(token)
        try:
            devices = paginate_devices(session, base)
        except requests.RequestException as e:
            logger.error(f"Failed to retrieve devices: {e}")
            return 1
        logger.info(f"Retrieved {len(devices)} devices")

    rows = []
    for d in devices:
        try:
            row = audit_device(session, base, d, args.stale_days, args.min_os)
            if row:
                rows.append(row)
        except Exception as e:
            logger.error(f"Error processing device {d.get('device_id', '?')}: {e}")

    try:
        write_csv(rows, args.output)
        summarize(rows, args.stale_days)
        logger.info(f"Audit complete: {args.output}")
        return 0
    except (ValueError, IOError, csv.Error):
        return 1


if __name__ == "__main__":
    sys.exit(main())
