#!/usr/bin/env python3
"""Okta user audit.

Exports every user with status, last login, group membership and enrolled MFA
factors to a CSV, and flags ACTIVE accounts that look stale (no login within
--stale-days). Read-only: it never changes anything in Okta.

WHAT YOU NEED TO PROVIDE (nothing is hard-coded in this file; never paste your
real values into it or commit them to GitHub):

  1. OKTA_ORG_URL   - your Okta org URL, e.g. https://your-org.okta.com
                      (the normal URL, NOT the -admin URL, no trailing path)
  2. OKTA_API_TOKEN - an Okta API token. Create one in Okta Admin Console:
                      Security > API > Tokens > Create token. Copy it once.

  Where to set them:
    - On your Mac (terminal):
        export OKTA_ORG_URL="https://your-org.okta.com"
        export OKTA_API_TOKEN="<paste token here, in your terminal only>"
    - In GitHub Actions: repo Settings > Secrets and variables > Actions >
        New repository secret. Create OKTA_ORG_URL and OKTA_API_TOKEN.

  Python package needed: requests   (pip install requests)

Usage:
    python okta_audit.py --stale-days 30 --output okta_audit.csv
"""
import argparse
import csv
import logging
import os
import re
import sys
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import requests

TIMEOUT = 30
MAX_RETRIES = 5

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger(__name__)


def validate_okta_url(url: str) -> bool:
    """Validate Okta organization URL format."""
    pattern = r'^https://[a-zA-Z0-9-]+\.okta\.com$'
    return bool(re.match(pattern, url.rstrip('/')))


def make_session(token: str) -> requests.Session:
    """Create an authenticated requests session."""
    if not token:
        raise ValueError("OKTA_API_TOKEN cannot be empty")
    s = requests.Session()
    s.headers.update({"Authorization": f"SSWS {token}", "Accept": "application/json"})
    return s


def api_get(session: requests.Session, url: str, params: Optional[Dict] = None) -> requests.Response:
    """GET with retry logic for Okta rate limiting (HTTP 429) and transient errors."""
    for attempt in range(MAX_RETRIES):
        try:
            resp = session.get(url, params=params, timeout=TIMEOUT)
            if resp.status_code == 429:
                # Check for Retry-After header, otherwise use X-Rate-Limit-Reset
                retry_after = resp.headers.get("Retry-After")
                if retry_after:
                    try:
                        sleep_time = int(retry_after)
                    except ValueError:
                        sleep_time = 5
                else:
                    reset = int(resp.headers.get("X-Rate-Limit-Reset", time.time() + 5))
                    sleep_time = min(max(reset - int(time.time()), 1) + 1, 60)
                logger.warning(f"Rate limited. Sleeping {sleep_time}s before retry {attempt + 1}/{MAX_RETRIES}")
                time.sleep(sleep_time)
                continue
            resp.raise_for_status()
            return resp
        except requests.exceptions.Timeout:
            logger.warning(f"Timeout on attempt {attempt + 1}/{MAX_RETRIES}")
            if attempt == MAX_RETRIES - 1:
                raise
            time.sleep(2 ** attempt)
        except requests.exceptions.RequestException as e:
            if attempt == MAX_RETRIES - 1:
                raise
            logger.warning(f"Request failed on attempt {attempt + 1}/{MAX_RETRIES}: {e}")
            time.sleep(2 ** attempt)
    raise RuntimeError(f"Failed after {MAX_RETRIES} retries: {url}")


def paginate(session: requests.Session, url: str, params: Optional[Dict] = None) -> List[Dict]:
    """Yield items from a paginated Okta list endpoint (follows Link: next)."""
    items = []
    while url:
        try:
            resp = api_get(session, url, params)
            data = resp.json()
            if isinstance(data, list):
                items.extend(data)
            params = None  # the 'next' link already carries the query string
            url = resp.links.get("next", {}).get("url")
        except (requests.RequestException, ValueError) as e:
            logger.error(f"Failed to paginate {url}: {e}")
            raise
    return items


def parse_time(value: Optional[str]) -> Optional[datetime]:
    """Parse ISO 8601 timestamp to datetime."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        logger.warning(f"Failed to parse timestamp: {value}")
        return None


def user_groups(session: requests.Session, base: str, user_id: str) -> List[str]:
    """Fetch group names for a user."""
    names = []
    try:
        groups = paginate(session, f"{base}/api/v1/users/{user_id}/groups")
        for g in groups:
            name = g.get("profile", {}).get("name") or g.get("id", "")
            if name:
                names.append(name)
    except requests.RequestException as e:
        logger.warning(f"Failed to fetch groups for user {user_id}: {e}")
    return sorted(names)


def user_factors(session: requests.Session, base: str, user_id: str) -> List[str]:
    """Fetch active MFA factors for a user."""
    out = []
    try:
        factors = paginate(session, f"{base}/api/v1/users/{user_id}/factors")
        for f in factors:
            if f.get("status") == "ACTIVE":
                factor_type = f.get("factorType", "?")
                provider = f.get("provider", "?")
                out.append(f"{factor_type}:{provider}")
    except requests.HTTPError as e:
        # Some tenants/users restrict this endpoint; leave blank
        logger.debug(f"Could not fetch factors for user {user_id}: {e}")
    except requests.RequestException as e:
        logger.warning(f"Unexpected error fetching factors for user {user_id}: {e}")
    return sorted(out)


def audit(session: requests.Session, base: str, stale_days: int) -> List[Dict[str, Any]]:
    """Perform audit of Okta users."""
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=stale_days)
    rows = []
    errors = 0

    logger.info(f"Starting audit with {stale_days}-day stale threshold")

    try:
        users = paginate(session, f"{base}/api/v1/users", {"limit": 200})
        logger.info(f"Retrieved {len(users)} users")
    except requests.RequestException as e:
        logger.error(f"Failed to retrieve users: {e}")
        raise

    for u in users:
        try:
            profile = u.get("profile", {})
            last_login = parse_time(u.get("lastLogin"))
            groups = user_groups(session, base, u["id"])
            factors = user_factors(session, base, u["id"])
            active = u.get("status") == "ACTIVE"
            stale = active and (last_login is None or last_login < cutoff)

            rows.append({
                "id": u.get("id", ""),
                "login": profile.get("login", ""),
                "name": f"{profile.get('firstName', '')} {profile.get('lastName', '')}".strip(),
                "email": profile.get("email", ""),
                "status": u.get("status", ""),
                "created": u.get("created", ""),
                "last_login": u.get("lastLogin") or "",
                "days_since_login": (now - last_login).days if last_login else "",
                "groups": "; ".join(groups),
                "mfa_factors": "; ".join(factors),
                "has_mfa": bool(factors),
                "stale": stale,
            })
        except Exception as e:
            errors += 1
            logger.error(f"Error processing user {u.get('id', 'unknown')}: {e}")

    if errors > 0:
        logger.warning(f"Encountered {errors} errors during audit")

    return rows


def write_csv(rows: List[Dict[str, Any]], path: str) -> None:
    """Write audit results to CSV file."""
    if not rows:
        logger.error("No users returned from audit")
        raise ValueError("Audit returned no users")

    try:
        with open(path, "w", newline="", encoding="utf-8") as fh:
            fieldnames = [
                "id", "login", "name", "email", "status", "created",
                "last_login", "days_since_login", "groups", "mfa_factors",
                "has_mfa", "stale"
            ]
            writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(rows)
        logger.info(f"Wrote {len(rows)} rows to {path}")
    except (IOError, csv.Error) as e:
        logger.error(f"Failed to write CSV: {e}")
        raise


def summarize(rows: List[Dict[str, Any]], stale_days: int, errors: int = 0) -> None:
    """Print audit summary."""
    active = [r for r in rows if r.get("status") == "ACTIVE"]
    stale_count = sum(1 for r in rows if r.get("stale", False))
    no_mfa_count = sum(1 for r in active if not r.get("has_mfa", False))

    logger.info(f"Users: {len(rows)}  Active: {len(active)}")
    logger.info(f"Stale (>{stale_days} days or never logged in): {stale_count}")
    logger.info(f"Active without MFA: {no_mfa_count}")
    if errors > 0:
        logger.warning(f"Errors encountered: {errors}")


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Read-only Okta user audit to CSV.")
    parser.add_argument("--stale-days", type=int, default=30,
                       help="Days of inactivity to consider an account stale")
    parser.add_argument("--output", default="okta_audit.csv",
                       help="Output CSV file path")
    parser.add_argument("--verbose", action="store_true",
                       help="Enable verbose logging")
    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    base = os.environ.get("OKTA_ORG_URL", "").rstrip("/")
    token = os.environ.get("OKTA_API_TOKEN", "")

    if not base:
        logger.error("OKTA_ORG_URL environment variable not set")
        return 1
    if not token:
        logger.error("OKTA_API_TOKEN environment variable not set")
        return 1
    if not validate_okta_url(base):
        logger.error(f"Invalid OKTA_ORG_URL format: {base}")
        return 1

    try:
        session = make_session(token)
        rows = audit(session, base, args.stale_days)
        write_csv(rows, args.output)
        summarize(rows, args.stale_days)
        logger.info(f"Audit complete: {args.output}")
        return 0
    except Exception as e:
        logger.error(f"Audit failed: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
