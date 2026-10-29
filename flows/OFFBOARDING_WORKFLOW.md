# Okta-to-Jira Offboarding Workflow

## Overview

This directory contains an Okta Workflows configuration that automates Jira Service Management ticket creation when users are deactivated in Okta.

## Implementation Details

**Format:** Okta Workflows (flopack format)
**File:** `okta-offboarding-jira-workflow.flow`
**Tool:** Okta Workflows (no-code automation platform)

## Workflow Configuration

### Trigger
- **Event:** User Deactivated
- **Source:** Okta User Lifecycle Events
- **Condition:** User status changes to `DEACTIVATED` or `SUSPENDED`

### Workflow Steps

1. **Okta Kernel** - Initialize workflow connection
2. **readUser** - Retrieve full user profile from Okta API
3. **String Concat** - Build ticket description from user data
4. **Jira2 createIssue** - Create service request in Jira Service Management
5. **Okta Kernel** - Finalize workflow

### Required Okta Configuration

1. **Enable User Lifecycle Events:**
   - Navigate to Okta Admin Console
   - Go to Settings > Notifications
   - Enable User Lifecycle event hooks for Workflows

2. **Create Workflow in Okta Workflows:**
   - Import the `.flow` file into Okta Workflows
   - Configure connection to your Okta tenant
   - Test trigger with a test user

### Required Jira Configuration

1. **Jira Service Management Project:**
   - Create or identify a Service Management project
   - Note the project key (e.g., `IT`, `HELP`)

2. **Request Type:**
   - Identify the request type for offboarding (e.g., "User Offboarding")
   - Note the request type ID

3. **Field Mappings:**
   - Map Okta user fields to Jira custom fields:
     - User email → Reporter/Requester
     - User name → Summary
     - User ID → Custom field
     - Last login → Custom field
     - Group memberships → Description

4. **API Token:**
   - Create Jira API token for the workflow connection
   - Store in Okta Workflows connection (not in this repo)

### Required Permissions

**Okta:**
- Read User API permission
- View Users group
- Access to User Lifecycle Events

**Jira:**
- Create Issues permission in target project
- API access with valid token
- Service Management agent access

### Testing Procedure

1. **Create Test User:**
   - Create a test user in Okta (e.g., `test-offboard@example.com`)
   - Add to relevant groups

2. **Deactivate Test User:**
   - Deactivate the test user in Okta Admin Console
   - Monitor Okta Workflows execution logs

3. **Verify Jira Ticket:**
   - Check Jira Service Management for new ticket
   - Verify all user data populated correctly
   - Confirm ticket assigned to correct team

4. **Clean Up:**
   - Close or delete test ticket
   - Reactivate or delete test user as needed

### Idempotency and Duplicate Prevention

**Current State:** The workflow does not implement idempotency checks.

**Risk:** If the same user is deactivated multiple times (e.g., reactivated then deactivated again), duplicate tickets may be created.

**Potential Improvements:**
- Add Jira query to check for existing open tickets for the user
- Use Okta user ID as unique identifier in Jira custom field
- Implement deduplication logic in workflow

### Failure Handling

**Okta API Errors:**
- Workflow logs will show API failures
- No retry logic built-in (Okta Workflows handles retries based on configuration)

**Jira API Errors:**
- Failed ticket creation will appear in workflow logs
- Manual intervention may be required
- Consider adding email alert on failure

### Troubleshooting

**Workflow not triggering:**
- Verify User Lifecycle Events are enabled in Okta
- Check Okta Workflows is properly connected
- Review workflow activation status

**Ticket not created in Jira:**
- Verify Jira connection credentials in Okta Workflows
- Check Jira API token is valid
- Review field mappings match Jira project configuration
- Check Jira project permissions

**Missing user data in ticket:**
- Verify Okta user profile is complete
- Check string concatenation logic in workflow
- Review Jira field mappings

### Security Considerations

- Jira API token stored in Okta Workflows connection (not in code)
- Workflow has read-only access to Okta user data
- No direct database access
- All API calls occur over HTTPS

### Limitations

- Requires Okta Workflows subscription
- Workflow runs in Okta's cloud, not on-premise
- No local testing capability without Okta tenant
- Changes require Okta Workflows UI access
