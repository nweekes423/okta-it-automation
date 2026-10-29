# Demo Script: Okta IT Automation End-to-End

This script demonstrates the complete workflow from user lifecycle event to audit findings to offboarding ticket creation.

## Prerequisites

- Okta organization with API access
- Test user account (e.g., `demo-offboard@example.com`)
- Jira Service Management project (for offboarding)
- This repository cloned and configured

---

## Part 1: Baseline Audit (Before Lifecycle Event)

**Goal:** Show the current state before any changes.

```bash
cd okta-it-automation

# Run audit to establish baseline
python okta_audit.py --stale-days 30 --output demo-baseline.csv

# Show results
cat demo-baseline.csv

# Note the test user's current status
grep "demo-offboard" demo-baseline.csv
```

**Expected Output:**
```
2024-10-12 14:00:00 - INFO - Starting audit with 30-day stale threshold
2024-10-12 14:00:05 - INFO - Retrieved 150 users
2024-10-12 14:00:20 - INFO - Users: 150  Active: 120
2024-10-12 14:00:20 - INFO - Stale (>30 days or never logged in): 5
2024-10-12 14:00:20 - INFO - Active without MFA: 2
```

**What to highlight in interview:**
- "This establishes our baseline security posture before the lifecycle event."
- "We have 120 active users, 5 stale accounts, and 2 without MFA."

---

## Part 2: Simulate User Lifecycle Event

**Option A: In a Non-Production Okta Tenant (Recommended)**

1. **Create Test User:**
   - Go to Okta Admin Console > Directory > People > Add Person
   - Create: `demo-offboard@example.com`
   - Add to relevant groups (e.g., "Engineering", "IT")
   - Status: STAGED or ACTIVE

2. **Deactivate the User:**
   - Select the test user
   - Click "Deactivate"
   - Confirm deactivation

3. **Verify Event:**
   - Go to Okta Admin Console > Reports > System Log
   - Filter by: User Lifecycle > User Deactivated
   - Confirm event appears for your test user

**Option B: Document the Process (If No Test Tenant)**

1. **Screenshot the Okta Admin Console:**
   - Show the user list with active users
   - Show the "Deactivate" button location
   - Show the confirmation dialog

2. **Document the Event:**
   - "In production, this would trigger the User Deactivated webhook"
   - "The Okta Workflows configuration listens for this event"
   - "See `flows/okta-offboarding-jira-workflow.flow` for the trigger definition"

**What to highlight in interview:**
- "In production, deactivating a user triggers the User Deactivated event in Okta"
- "This event is caught by the Okta Workflows integration"
- "The workflow then creates a Jira ticket automatically"

---

## Part 3: Post-Event Audit

**Goal:** Show the audit detects the lifecycle change.

```bash
# Run audit after deactivation
python okta_audit.py --stale-days 30 --output demo-after.csv

# Compare with baseline
diff demo-baseline.csv demo-after.csv

# Show the changed user
grep "demo-offboard" demo-after.csv
```

**Expected Output:**
```
The test user now shows status as DEACTIVATED or SUSPENDED
```

**What to highlight in interview:**
- "The audit now shows the user with status DEACTIVATED"
- "This provides an audit trail of who was deactivated and when"
- "The CSV is timestamped and can be used for compliance reporting"

---

## Part 4: Offboarding Workflow Demonstration

**Option A: Show the Workflow Configuration**

```bash
# Show the workflow file exists
ls -la flows/okta-offboarding-jira-workflow.flow

# Show the workflow documentation
cat flows/OFFBOARDING_WORKFLOW.md

# Extract and show the trigger configuration
python3 -c "
import json
with open('flows/okta-offboarding-jira-workflow.flow', 'r') as f:
    data = json.load(f)
flow = data['data']['flos']['08b480eb-a60e-45df-b540-514c2df764ee']
print('Trigger:', flow['data']['display']['eventConnecterName'])
print('Modules:')
for module in flow['data']['display']['preview']:
    print(f'  - {module[\"module\"]}: {module[\"name\"] or \"(kernel)\"}')"
```

**Expected Output:**
```
Trigger: User Deactivated
Modules:
  - okta: (kernel)
  - okta: readUser
  - jira2: createIssue
  - string: concat
  - okta: (kernel)
```

**What to highlight in interview:**
- "The workflow triggers on User Deactivated events"
- "It reads the user details from Okta API"
- "It creates a Jira issue using the Jira2 module"
- "The string concat builds the ticket description from user data"

**Option B: Show Jira Ticket (If Test Jira Available)**

1. **Go to Jira Service Management:**
   - Navigate to your offboarding project
   - Look for the newly created ticket
   - Verify it contains the user's details

2. **Screenshot the Ticket:**
   - Show the ticket summary (user name)
   - Show the description (user email, groups, last login)
   - Show the assignment to the correct team

3. **Document the Field Mappings:**
   - "The workflow maps Okta user fields to Jira custom fields"
   - "See OFFBOARDING_WORKFLOW.md for the complete mapping"

**What to highlight in interview:**
- "When the user was deactivated, a Jira ticket was automatically created"
- "The ticket contains all relevant user information for the offboarding team"
- "This ensures no manual steps are forgotten during high-pressure departures"

---

## Part 5: GitHub Actions CI/CD Demonstration

**Goal:** Show the automated pipeline.

```bash
# Go to GitHub Actions
# URL: https://github.com/nweekes423/okta-it-automation/actions

# Manually trigger the workflow
# 1. Click "Okta User Audit" workflow
# 2. Click "Run workflow" button
# 3. Click green "Run workflow" button

# Watch the execution
# - Test job runs pytest (should pass)
# - Audit job runs okta_audit.py (should pass)
# - Artifact uploaded (okta-audit.zip)
```

**What to highlight in interview:**
- "The GitHub Actions workflow runs tests before the production audit"
- "This prevents bad code from running against the Okta tenant"
- "The audit runs daily at 2 PM UTC, with manual trigger available"
- "Artifacts are retained for 7 days for compliance review"

---

## Part 6: Clean Up

```bash
# Remove demo CSV files
rm demo-baseline.csv demo-after.csv

# Reactivate or delete test user in Okta (if needed)
# - Go to Okta Admin Console > Directory > People
# - Select test user > Reactivate or Delete

# Close or delete test Jira ticket (if created)
# - Go to Jira > Select ticket > Close/Delete
```

---

## Interview Talking Points

**1. End-to-End Automation:**
"I demonstrated the complete lifecycle: baseline audit → user deactivation → post-event audit → Jira ticket creation. The audit provides visibility, while the workflow ensures action."

**2. Security & Compliance:**
"The audit is read-only and runs daily, giving us continuous monitoring of security posture. The CSV output provides an audit trail for compliance purposes."

**3. Reliability:**
"The GitHub Actions workflow runs tests before the production audit, ensuring code quality. The offboarding workflow is event-driven, so it doesn't depend on schedules or manual triggers."

**4. Scalability:**
"The pagination logic handles Okta tenants of any size. The rate limiting prevents API abuse even with thousands of users."

**5. Operational Excellence:**
"All configuration is via environment variables, never hardcoded. The workflow documentation provides clear setup and troubleshooting steps for any team member."

---

## Screenshots to Capture

1. **Baseline Audit Output** - Terminal showing CSV with user count
2. **Okta User Deactivation** - Admin Console showing deactivate action
3. **Post-Event Audit** - Terminal showing changed user status
4. **Workflow Configuration** - Okta Workflows UI showing trigger and steps
5. **Jira Ticket** - Service Management ticket with user details
6. **GitHub Actions** - Workflow run showing test and audit jobs passing
7. **Artifact Download** - CSV artifact available for download

---

## Demo Flow Summary

1. **Setup** (30 seconds): Show repo structure and README
2. **Baseline Audit** (1 minute): Run audit, show CSV
3. **Lifecycle Event** (2 minutes): Deactivate user in Okta
4. **Post-Event Audit** (1 minute): Run audit, show change
5. **Offboarding Workflow** (2 minutes): Show workflow config or Jira ticket
6. **CI/CD Pipeline** (1 minute): Show GitHub Actions
7. **Clean Up** (30 seconds): Remove demo files

**Total Time:** ~8 minutes

---

## Troubleshooting

**If workflow doesn't trigger:**
- Verify User Lifecycle Events enabled in Okta
- Check Okta Workflows connection status
- Review OFFBOARDING_WORKFLOW.md troubleshooting section

**If Jira ticket not created:**
- Verify Jira API token in Okta Workflows
- Check Jira project permissions
- Review field mappings in workflow

**If GitHub Actions fails:**
- Check secrets are configured in repo settings
- Verify test suite passes locally first
- Review workflow logs in Actions tab