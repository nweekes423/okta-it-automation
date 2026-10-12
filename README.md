# Okta IT Automation

A collection of tools and workflows for automating Okta identity management tasks, including user auditing and offboarding automation.

## Overview

This repository provides automation solutions for common Okta administrative tasks:

- **User Audit Script** - A Python tool that exports Okta user data to CSV, identifying stale accounts and users without MFA
- **Offboarding Workflow** - An automated workflow that creates Jira tickets when users are deactivated in Okta
- **GitHub Actions Integration** - Scheduled automated audits with artifact retention

## Features

### User Audit (`okta_audit.py`)

A read-only Python script that:
- Exports all Okta users with status, last login, group membership, and MFA factors to CSV
- Flags ACTIVE accounts that haven't logged in within a configurable threshold (default: 30 days)
- Identifies users without MFA enrolled
- Uses Okta's API with rate limiting and pagination support

**Usage:**
```bash
python okta_audit.py --stale-days 30 --output okta_audit.csv
```

**Required Environment Variables:**
- `OKTA_ORG_URL` - Your Okta org URL (e.g., https://your-org.okta.com)
- `OKTA_API_TOKEN` - Okta API token (create in Admin Console > Security > API > Tokens)

### Offboarding Workflow

An automated workflow that:
- Triggers when a user is deactivated in Okta
- Retrieves user details and creates a corresponding Jira ticket
- Integrates Okta and Jira for streamlined offboarding processes

### GitHub Actions

The repository includes a GitHub Actions workflow that:
- Runs the user audit automatically on weekdays at 2 PM UTC
- Stores audit results as artifacts with 7-day retention
- Supports manual triggering via the Actions UI

## Setup

1. Clone the repository
2. Install Python dependencies:
   ```bash
   pip install requests
   ```
3. Set your Okta credentials as environment variables or GitHub secrets
4. Run the audit script or enable the GitHub Actions workflow

## Security

- All scripts are read-only and do not modify Okta data
- API tokens should be stored as environment variables or GitHub secrets, never committed to the repository
- CSV output files are excluded from version control via .gitignore

## License

See LICENSE file for details.
