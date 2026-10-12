#!/usr/bin/env python3
"""Okta user audit.

Exports every user with status, last login, group membership and enrolled MFA
factors to a CSV, and flags ACTIVE accounts that look stale (no login within
--stale-days). Read-only: it never changes anything in Okta.

WHAT YOU NEED TO PROVIDE (nothing is hard-coded in this file; never paste your
real values into it or commit them to GitHub):

  1. OKTA_ORG_URL   - your Okta org URL, e.g. https://integrator-4804661.okta.com
                      (the normal URL, NOT the -admin URL, no trailing path)
  2. OKTA_API_TOKEN - an Okta API token. Create one in Okta Admin Console:
                      Security > API > Tokens > Create token. Copy it once.

  Where to set them:
    - On your Mac (terminal):
        export OKTA_ORG_URL="https://integrator-4804661.okta.com"
        export OKTA_API_TOKEN="<paste token here, in your terminal only>"
    - In GitHub Actions: repo Settings > Secrets and variables > Actions >
        New repository secret. Create OKTA_ORG_URL and OKTA_API_TOKEN.

  Python package needed: requests   (pip install requests)

Usage:
    python okta_audit.py --stale-days 30 --output okta_audit.csv
"""
import argparse
import csv
import os
import sys
import time
from datetime import datetime, timedelta, timezone

import requests

TIMEOUT = 30
MAX_RETRIES = 5


def make_session(token):
    s = requests.Session()
    s.headers.update({"Authorization": f"SSWS {token}", "Accept": "application/json"})
    return s


def api_get(session, url, params=None):
    """GET with simple handling for Okta rate limiting (HTTP 429)."""
    for _ in range(MAX_RETRIES):
        resp = session.get(url, params=params, timeout=TIMEOUT)
        if resp.status_code == 429:
            reset = int(resp.headers.get("X-Rate-Limit-Reset", time.time() + 5))
            time.sleep(min(max(reset - int(time.time()), 1) + 1, 60))
            continue
        resp.raise_for_status()
        return resp
    raise RuntimeError(f"Rate limited too many times: {url}")


def paginate(session, url, params=None):
    """Yield items from a paginated Okta list endpoint (follows Link: next)."""
    while url:
        resp = api_get(session, url, params)
        yield from resp.json()
        params = None  # the 'next' link already carries the query string
        url = resp.links.get("next", {}).get("url")


def parse_time(value):
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def user_groups(session, base, user_id):
    names = []
    for g in paginate(session, f"{base}/api/v1/users/{user_id}/groups"):
        names.append(g.get("profile", {}).get("name", g.get("id", "")))
    return sorted(names)


def user_factors(session, base, user_id):
    out = []
    try:
        for f in paginate(session, f"{base}/api/v1/users/{user_id}/factors"):
            if f.get("status") == "ACTIVE":
                out.append(f"{f.get('factorType', '?')}:{f.get('provider', '?')}")
    except requests.HTTPError:
        pass  # some tenants/users restrict this endpoint; leave blank
    return sorted(out)


def audit(session, base, stale_days):
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=stale_days)
    rows = []
    for u in paginate(session, f"{base}/api/v1/users", {"limit": 200}):
        profile = u.get("profile", {})
        last_login = parse_time(u.get("lastLogin"))
        groups = user_groups(session, base, u["id"])
        factors = user_factors(session, base, u["id"])
        active = u.get("status") == "ACTIVE"
        stale = active and (last_login is None or last_login < cutoff)
        rows.append({
            "id": u["id"],
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
    return rows


def write_csv(rows, path):
    if not rows:
        print("No users returned.")
        return
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def summarize(rows, stale_days):
    active = [r for r in rows if r["status"] == "ACTIVE"]
    print(f"Users: {len(rows)}  Active: {len(active)}")
    print(f"Stale (>{stale_days} days or never logged in): {sum(r['stale'] for r in rows)}")
    print(f"Active without MFA: {sum(1 for r in active if not r['has_mfa'])}")


def main():
    p = argparse.ArgumentParser(description="Read-only Okta user audit to CSV.")
    p.add_argument("--stale-days", type=int, default=30)
    p.add_argument("--output", default="okta_audit.csv")
    args = p.parse_args()

    base = os.environ.get("OKTA_ORG_URL", "").rstrip("/")
    token = os.environ.get("OKTA_API_TOKEN", "")
    if not base or not token:
        sys.exit(
            "Missing settings. Set these environment variables first:\n"
            "  OKTA_ORG_URL   (e.g. https://your-org.okta.com)\n"
            "  OKTA_API_TOKEN (Okta Admin > Security > API > Tokens)\n"
            "See the top of this file for details."
        )

    rows = audit(make_session(token), base, args.stale_days)
    write_csv(rows, args.output)
    summarize(rows, args.stale_days)
    print(f"Wrote {args.output}")


if __name__ == "__main__":
    main()
