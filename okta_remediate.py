#!/usr/bin/env python3
"""Okta stale-account remediation.

Reads the CSV produced by okta_audit.py, selects ACTIVE accounts flagged as
stale, and remediates them through the Okta lifecycle API:

  1. Revoke all active sessions      DELETE /api/v1/users/{id}/sessions
  2. Remove enrolled MFA factors     DELETE /api/v1/users/{id}/factors/{fid}
                                     (only with --remove-factors)
  3. Deactivate the user             POST  /api/v1/users/{id}/lifecycle/deactivate

This is the enforcement half of the audit -> review -> remediate pipeline.
It is deliberately separate from okta_audit.py, which stays read-only.

SAFETY MODEL
  - Dry-run is the DEFAULT. Nothing is changed unless you pass --execute.
  - --exclude lets you protect accounts by login substring (service accounts,
    shared mailboxes, break-glass admins, etc.). Always exclude your own
    admin account before running with --execute.
  - Deactivation is reversible in Okta Admin (user can be reactivated), but
    revoked sessions and deleted factors are not.

WHAT YOU NEED (same as okta_audit.py):
  OKTA_ORG_URL   - e.g. https://your-org.okta.com
  OKTA_API_TOKEN - Okta API token with manage-users scope. Create in
                   Admin Console: Security > API > Tokens > Create token.
                   The token needs the 'okta.users.manage' scope (or the
                   legacy super-admin permission) for lifecycle changes.

Usage:
    # 1. Audit (read-only)
    python okta_audit.py --stale-days 30 --output okta_audit.csv

    # 2. Review the CSV, then preview what WOULD happen (default, safe)
    python okta_remediate.py --input okta_audit.csv \
        --exclude "admin,svc-,breakglass"

    # 3. Execute for real
    python okta_remediate.py --input okta_audit.csv --execute \
        --exclude "admin,svc-,breakglass" --remove-factors \
        --output okta_remediation.csv
"""
import argparse
import csv
import logging
import os
import sys
import time
from typing import Any, Dict, List, Optional

import requests

from okta_audit import (
    MAX_RETRIES,
    TIMEOUT,
    make_session,
    paginate,
    validate_okta_url,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger(__name__)

REQUIRED_COLUMNS = {"id", "login", "name", "status", "stale"}


def api_request(
    session: requests.Session,
    method: str,
    url: str,
    **kwargs: Any,
) -> requests.Response:
    """HTTP request with retry logic for Okta rate limiting (HTTP 429).

    Used for writes (DELETE/POST), unlike okta_audit.api_get which is GET-only.
    """
    for attempt in range(MAX_RETRIES):
        try:
            resp = session.request(method, url, timeout=TIMEOUT, **kwargs)
            if resp.status_code == 429:
                retry_after = resp.headers.get("Retry-After")
                if retry_after:
                    try:
                        sleep_time = int(retry_after)
                    except ValueError:
                        sleep_time = 5
                else:
                    reset = int(resp.headers.get("X-Rate-Limit-Reset", time.time() + 5))
                    sleep_time = min(max(reset - int(time.time()), 1) + 1, 60)
                logger.warning(
                    f"Rate limited on {method} {url}. "
                    f"Sleeping {sleep_time}s before retry {attempt + 1}/{MAX_RETRIES}"
                )
                time.sleep(sleep_time)
                continue
            resp.raise_for_status()
            return resp
        except requests.exceptions.Timeout:
            logger.warning(f"Timeout on {method} {url} (attempt {attempt + 1}/{MAX_RETRIES})")
            if attempt == MAX_RETRIES - 1:
                raise
            time.sleep(2 ** attempt)
        except requests.exceptions.RequestException as e:
            # 4xx other than 429 are not retryable
            if isinstance(e, requests.exceptions.HTTPError) and e.response is not None \
                    and 400 <= e.response.status_code < 500:
                raise
            if attempt == MAX_RETRIES - 1:
                raise
            logger.warning(f"{method} {url} failed (attempt {attempt + 1}/{MAX_RETRIES}): {e}")
            time.sleep(2 ** attempt)
    raise RuntimeError(f"Failed after {MAX_RETRIES} retries: {method} {url}")


def load_audit_csv(path: str) -> List[Dict[str, str]]:
    """Load rows from an okta_audit.py CSV output file."""
    try:
        with open(path, newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            missing = REQUIRED_COLUMNS - set(reader.fieldnames or [])
            if missing:
                raise ValueError(f"CSV missing required columns: {sorted(missing)}")
            return list(reader)
    except (IOError, csv.Error) as e:
        logger.error(f"Failed to read audit CSV {path}: {e}")
        raise


def select_targets(
    rows: List[Dict[str, str]],
    exclude: Optional[List[str]] = None,
    only: Optional[List[str]] = None,
) -> List[Dict[str, str]]:
    """Pick stale ACTIVE rows, honoring --exclude substrings and --only logins."""
    exclude = [e.lower() for e in (exclude or [])]
    only = {o.lower() for o in (only or [])}
    targets = []
    for row in rows:
        if row.get("stale", "").strip().lower() not in ("true", "1", "yes"):
            continue
        if row.get("status", "").strip().upper() != "ACTIVE":
            continue
        login = row.get("login", "")
        login_l = login.lower()
        if only and login_l not in only and not any(o in login_l for o in only):
            continue
        if any(e in login_l for e in exclude):
            logger.info(f"Skipping {login} (matches --exclude)")
            continue
        targets.append(row)
    return targets


def user_factor_ids(session: requests.Session, base: str, user_id: str) -> List[str]:
    """Fetch IDs of a user's ACTIVE MFA factors."""
    ids = []
    try:
        factors = paginate(session, f"{base}/api/v1/users/{user_id}/factors")
        for f in factors:
            if f.get("status") == "ACTIVE" and f.get("id"):
                ids.append(f["id"])
    except requests.RequestException as e:
        logger.warning(f"Could not fetch factors for user {user_id}: {e}")
    return ids


def remediate_user(
    session: requests.Session,
    base: str,
    user_id: str,
    remove_factors: bool = False,
) -> Dict[str, Any]:
    """Revoke sessions, optionally remove factors, then deactivate a user.

    Returns a result dict: {"actions": [...], "error": str|None}
    """
    result: Dict[str, Any] = {"actions": [], "error": None}

    try:
        api_request(session, "DELETE", f"{base}/api/v1/users/{user_id}/sessions")
        result["actions"].append("sessions_revoked")
    except requests.RequestException as e:
        result["error"] = f"revoke sessions failed: {e}"
        return result

    if remove_factors:
        factor_ids = user_factor_ids(session, base, user_id)
        for fid in factor_ids:
            try:
                api_request(session, "DELETE", f"{base}/api/v1/users/{user_id}/factors/{fid}")
                result["actions"].append("factor_removed")
            except requests.RequestException as e:
                logger.warning(f"Failed to remove factor {fid} for {user_id}: {e}")
                result["actions"].append("factor_remove_failed")

    try:
        api_request(session, "POST", f"{base}/api/v1/users/{user_id}/lifecycle/deactivate")
        result["actions"].append("deactivated")
    except requests.RequestException as e:
        result["error"] = f"deactivate failed: {e}"
    return result


def write_report(rows: List[Dict[str, Any]], path: str) -> None:
    """Write remediation results to CSV."""
    fieldnames = ["login", "name", "email", "days_since_login", "actions", "error"]
    try:
        with open(path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(rows)
        logger.info(f"Wrote remediation report to {path}")
    except (IOError, csv.Error) as e:
        logger.error(f"Failed to write report: {e}")
        raise


def parse_list(value: Optional[str]) -> Optional[List[str]]:
    """Split a comma-separated CLI arg into a list."""
    if not value:
        return None
    return [v.strip() for v in value.split(",") if v.strip()]


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Remediate stale Okta accounts from an audit CSV. "
                    "Dry-run by default; pass --execute to apply changes."
    )
    parser.add_argument("--input", required=True,
                        help="Path to okta_audit.py CSV output")
    parser.add_argument("--output", default="okta_remediation.csv",
                        help="Remediation report CSV path")
    parser.add_argument("--execute", action="store_true",
                        help="Actually perform changes (default is dry-run)")
    parser.add_argument("--remove-factors", action="store_true",
                        help="Also delete enrolled MFA factors before deactivating")
    parser.add_argument("--exclude", default="",
                        help="Comma-separated login substrings to never touch "
                             "(e.g. 'admin,svc-,breakglass')")
    parser.add_argument("--only", default="",
                        help="Comma-separated logins to limit remediation to")
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
        rows = load_audit_csv(args.input)
    except (ValueError, IOError, csv.Error):
        return 1

    targets = select_targets(rows, parse_list(args.exclude), parse_list(args.only))

    if not targets:
        logger.info("No stale accounts selected. Nothing to do.")
        return 0

    mode = "EXECUTE" if args.execute else "DRY-RUN"
    logger.info(f"{mode}: {len(targets)} stale account(s) selected")
    for t in targets:
        logger.info(f"  - {t.get('login')} ({t.get('name')}, "
                    f"last login {t.get('last_login') or 'never'})")

    if not args.execute:
        logger.info("Dry-run only. Re-run with --execute to apply changes.")
        return 0

    session = make_session(token)
    report = []
    failures = 0
    for t in targets:
        logger.info(f"Remediating {t.get('login')} ...")
        res = remediate_user(session, base, t["id"], args.remove_factors)
        if res["error"]:
            failures += 1
            logger.error(f"  FAILED for {t.get('login')}: {res['error']}")
        else:
            logger.info(f"  OK: {', '.join(res['actions'])}")
        report.append({
            "login": t.get("login", ""),
            "name": t.get("name", ""),
            "email": t.get("email", ""),
            "days_since_login": t.get("days_since_login", ""),
            "actions": "; ".join(res["actions"]),
            "error": res["error"] or "",
        })

    try:
        write_report(report, args.output)
    except (IOError, csv.Error):
        return 1

    if failures:
        logger.error(f"Completed with {failures} failure(s). See {args.output}")
        return 1
    logger.info(f"Remediation complete: {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
