#!/usr/bin/env python3
"""AI-assisted triage for IT audit findings.

Reads the CSVs produced by okta_audit.py and device_audit.py, sends a
compact, privacy-conscious summary to the Anthropic API, and produces a
prioritized findings report with recommended actions.

This is decision SUPPORT, not automation: it never touches Okta, Kandji,
or any other system. A human reviews the report and decides what to act
on — the same human-in-the-loop pattern as okta_remediate.py's dry-run.

WHAT YOU NEED (never commit real values):
  ANTHROPIC_API_KEY - Anthropic API key (console.anthropic.com)
  ANTHROPIC_MODEL   - optional, defaults to a Haiku-class model

Usage:
    python ai_triage.py --input okta_audit.csv --input device_audit.csv \
        --output triage_report.md
    python ai_triage.py --input okta_audit.csv --demo   # no API key needed
"""
import argparse
import csv
import logging
import os
import sys
import time
from collections import Counter
from typing import Any, Dict, List, Optional

import requests

TIMEOUT = 60
MAX_RETRIES = 4
ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_VERSION = "2023-06-01"
DEFAULT_MODEL = "claude-3-5-haiku-20241022"
MAX_TOKENS = 2048
MAX_FLAGGED_ROWS = 50

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger(__name__)


SYSTEM_PROMPT = """You are an IT operations analyst reviewing automated audit
findings for a ~150-person company. You produce concise, prioritized
triage reports for a human IT engineer who will decide what to act on.

Rules:
- Prioritize by risk: active security exposure first, then lifecycle
  hygiene, then cleanup.
- Distinguish findings that can be automated (e.g. stale account
  deactivation) from ones needing human investigation (e.g. stalled
  onboarding, lost devices).
- Recommend concrete next actions, including which existing tool to use
  (okta_audit.py, okta_remediate.py, device_audit.py) where relevant.
- Flag anything ambiguous or requiring manager/security escalation.
- Keep it under 400 words. Use markdown with headers and bullets.
- Do NOT include raw personal data beyond what is needed to identify the
  account or device (login/email/serial is fine; never invent data)."""


# Load any audit CSV produced by this repo's scripts into a list of dicts.
def load_csv(path: str) -> List[Dict[str, str]]:
    """Load any audit CSV produced by this repo's scripts."""
    # DictReader turns each CSV row into a dict keyed by the header names,
    # so all values arrive as strings ("True"/"False", not booleans).
    try:
        with open(path, newline="", encoding="utf-8") as fh:
            return list(csv.DictReader(fh))
    except (IOError, csv.Error) as e:
        logger.error(f"Failed to read {path}: {e}")
        raise


# Identify which script produced a CSV by looking at its column names.
def detect_dataset(rows: List[Dict[str, str]], path: str) -> str:
    """Guess which audit produced this CSV from its columns."""
    # Each script writes a distinct set of column names, so we can identify
    # the source without any explicit flag: devices have device_id, the Okta
    # audit has mfa_factors/days_since_login.
    cols = set(rows[0].keys()) if rows else set()
    if "device_id" in cols:
        return "devices"
    if "mfa_factors" in cols or "days_since_login" in cols:
        return "okta_users"
    logger.warning(f"Unrecognized CSV format for {path}; treating as generic")
    return "generic"


# Pick only the rows worth sending to the LLM — keeps the prompt small and limits PII exposure.
def flagged_rows(rows: List[Dict[str, str]], dataset: str) -> List[Dict[str, str]]:
    """Extract the rows worth sending to the LLM (capped).

    We only send interesting rows rather than the whole CSV: it keeps the
    prompt small (cheaper, faster) and avoids shipping every user's PII to
    a third-party API. MAX_FLAGGED_ROWS is a hard cap as a safety valve.
    """
    out = []
    for r in rows:
        if dataset == "okta_users":
            # A user is "interesting" if they are stale, stalled, or an
            # ACTIVE account missing MFA — the three finding types the
            # audit produces.
            interesting = (
                r.get("stale", "").lower() == "true"
                or r.get("stalled", "").lower() == "true"
                or (r.get("status") == "ACTIVE"
                    and r.get("has_mfa", "").lower() != "true")
            )
        elif dataset == "devices":
            # Device rows carry a precomputed "flags" column; any content
            # means the device needs attention.
            interesting = bool(r.get("flags", "").strip())
        else:
            interesting = any(
                r.get(c, "").lower() in ("true", "yes")
                for c in ("stale", "stalled", "noncompliant")
            )
        if interesting:
            out.append(r)
    return out[:MAX_FLAGGED_ROWS]


# Assemble the compact evidence summary (counts + flagged rows) that goes into the prompt.
def build_context(inputs: List[Dict[str, Any]]) -> str:
    """Build the compact evidence summary sent to the model.

    Sends aggregate counts plus the flagged rows only — enough for the
    model to prioritize and recommend, without dumping the entire
    inventory (and all its PII) into the prompt.
    """
    parts = []
    for item in inputs:
        dataset = item["dataset"]
        rows = item["rows"]
        flagged = item["flagged"]
        parts.append(f"## Dataset: {dataset} ({item['path']})")
        parts.append(f"Total rows: {len(rows)}  Flagged/interesting: {len(flagged)}")

        if dataset == "okta_users":
            # Aggregate stats let the model reason about scale ("5 stale
            # accounts out of 150" means something different than "5 out
            # of 6") without needing every row.
            status_counts = Counter(r.get("status", "?") for r in rows)
            parts.append("Status counts: " +
                         ", ".join(f"{k}={v}" for k, v in status_counts.most_common()))
            stale = sum(1 for r in rows if r.get("stale", "").lower() == "true")
            stalled = sum(1 for r in rows if r.get("stalled", "").lower() == "true")
            no_mfa = sum(1 for r in rows
                         if r.get("status") == "ACTIVE"
                         and r.get("has_mfa", "").lower() != "true")
            parts.append(f"Stale ACTIVE accounts: {stale}")
            parts.append(f"Stalled lifecycle accounts: {stalled}")
            parts.append(f"Active accounts without MFA: {no_mfa}")
        elif dataset == "devices":
            # Count each flag across all devices so the model can see the
            # most common compliance gaps at a glance.
            flag_counts = Counter()
            for r in rows:
                for f in filter(None, r.get("flags", "").split("; ")):
                    flag_counts[f.strip()] += 1
            parts.append("Flag counts: " +
                         ", ".join(f"{k}={v}" for k, v in flag_counts.most_common()))

        if flagged:
            # Per-row detail for flagged items only, formatted differently
            # per dataset so the model sees the fields that matter.
            parts.append("Flagged rows (login/device, status/flags):")
            for r in flagged[:MAX_FLAGGED_ROWS]:
                if dataset == "devices":
                    parts.append(
                        f"- {r.get('name','?')} ({r.get('serial','?')}): "
                        f"{r.get('flags','')}"
                    )
                else:
                    parts.append(
                        f"- {r.get('login','?')} [{r.get('status','?')}]: "
                        f"stale={r.get('stale','')} stalled={r.get('stalled','')} "
                        f"mfa={r.get('has_mfa','')} groups={r.get('groups','')}"
                    )
        parts.append("")
    return "\n".join(parts)


# Send the prompt to the Anthropic Messages API and return the report text, retrying on rate limits.
def call_anthropic(prompt: str, api_key: str, model: str) -> str:
    """Call the Anthropic Messages API with retry on rate limits."""
    headers = {
        "x-api-key": api_key,
        "anthropic-version": ANTHROPIC_VERSION,
        "content-type": "application/json",
    }
    payload = {
        "model": model,
        "max_tokens": MAX_TOKENS,
        "system": SYSTEM_PROMPT,
        "messages": [{"role": "user", "content": prompt}],
    }
    for attempt in range(MAX_RETRIES):
        try:
            resp = requests.post(ANTHROPIC_URL, headers=headers,
                                 json=payload, timeout=TIMEOUT)
            if resp.status_code == 429:
                # Anthropic returns Retry-After on rate limits; honor it
                # rather than hammering the API.
                retry_after = resp.headers.get("Retry-After", "5")
                try:
                    sleep_time = int(retry_after)
                except ValueError:
                    sleep_time = 5
                logger.warning(f"Rate limited. Sleeping {sleep_time}s")
                time.sleep(sleep_time)
                continue
            resp.raise_for_status()
            data = resp.json()
            # The Messages API returns content as a list of blocks; we only
            # want the text blocks concatenated into the final report.
            return "".join(
                block.get("text", "")
                for block in data.get("content", [])
                if block.get("type") == "text"
            )
        except requests.exceptions.RequestException as e:
            if attempt == MAX_RETRIES - 1:
                raise
            logger.warning(f"API call failed (attempt {attempt + 1}): {e}")
            time.sleep(2 ** attempt)
    raise RuntimeError("Anthropic API call failed after retries")


# Produce a clearly-labeled template report when --demo is used, so no API key is needed.
def demo_report(inputs: List[Dict[str, Any]]) -> str:
    """Generate a labeled template report when --demo is used (no API call).

    Lets the script be demoed and tested without an Anthropic key. The
    output is clearly labeled as a template so it can't be mistaken for
    real LLM analysis.
    """
    lines = [
        "# IT Audit Triage Report (DEMO — template, no LLM)",
        "",
        "*This report was generated in --demo mode. A real run sends the",
        "evidence summary below to Claude and returns prioritized findings.*",
        "",
        "## Evidence summary",
        "",
        build_context(inputs),
        "## What a real report would contain",
        "",
        "- **Priority 1 — Security exposure:** stale ACTIVE accounts and",
        "  devices in Lost Mode, with recommended remediation commands",
        "- **Priority 2 — Lifecycle hygiene:** stalled PROVISIONED /",
        "  PASSWORD_EXPIRED accounts needing human outreach",
        "- **Priority 3 — Cleanup:** noncompliant devices (FileVault off,",
        "  agent missing, OS below floor) with suggested runbook actions",
        "- **Escalations:** anything ambiguous flagged for manager review",
    ]
    return "\n".join(lines)


# CLI entry point: load CSVs, build context, call the API (or demo), write the markdown report.
def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="AI-assisted triage of IT audit CSVs (read-only analysis)."
    )
    parser.add_argument("--input", action="append", required=True,
                        help="Path to an audit CSV (repeatable)")
    parser.add_argument("--output", default="triage_report.md",
                        help="Output markdown report path")
    parser.add_argument("--model", default=os.environ.get(
        "ANTHROPIC_MODEL", DEFAULT_MODEL),
        help="Anthropic model ID")
    parser.add_argument("--demo", action="store_true",
                        help="Generate a template report without calling the API")
    parser.add_argument("--verbose", action="store_true",
                        help="Enable verbose logging")
    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    inputs = []
    for path in args.input:
        try:
            rows = load_csv(path)
        except (IOError, csv.Error):
            return 1
        if not rows:
            logger.warning(f"{path} is empty; skipping")
            continue
        dataset = detect_dataset(rows, path)
        inputs.append({
            "path": path,
            "dataset": dataset,
            "rows": rows,
            "flagged": flagged_rows(rows, dataset),
        })

    if not inputs:
        logger.error("No usable input data")
        return 1

    # --demo skips the API entirely; otherwise we need a key and we send
    # only the compact evidence summary (counts + flagged rows), never the
    # raw CSVs.
    if args.demo:
        report = demo_report(inputs)
    else:
        api_key = os.environ.get("ANTHROPIC_API_KEY", "")
        if not api_key:
            logger.error("ANTHROPIC_API_KEY environment variable not set "
                         "(or use --demo)")
            return 1
        prompt = (
            "Triage the following audit findings and produce the report.\n\n"
            + build_context(inputs)
        )
        try:
            report = call_anthropic(prompt, api_key, args.model)
        except requests.RequestException as e:
            logger.error(f"Anthropic API call failed: {e}")
            return 1

    try:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(report if report.endswith("\n") else report + "\n")
        logger.info(f"Wrote triage report to {args.output}")
        return 0
    except IOError as e:
        logger.error(f"Failed to write report: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
