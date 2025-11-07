# Microsoft 365 Audit Scripts Documentation

**Location:** `/Scripts/`
**Purpose:** Comprehensive Microsoft 365 security and compliance audit toolkit
**Last Updated:** November 5, 2025

---

## Overview

This collection of PowerShell scripts performs a comprehensive audit of your Microsoft 365 environment, identifying security vulnerabilities, compliance gaps, and governance issues. The scripts are designed to be run sequentially, with each script focusing on a specific aspect of your M365 tenant.

---

## Scripts Summary

### Setup Scripts
- **Troubleshoot-Setup.ps1** - Verifies PowerShell environment, checks execution policy, unblocks scripts, and tests module installation
- **00a-Register-PnP-App.ps1** - One-time registration of custom Azure AD app for PnP PowerShell authentication (required since Microsoft deprecated default app)
- **00-Connect-M365.ps1** - Establishes connections to Microsoft Graph, Exchange Online, SharePoint, and Teams with proper permissions
- **simple-connect.ps1** - Quick Microsoft Graph connection test for troubleshooting authentication issues

### Audit Scripts
- **01-Export-Users.ps1** - Exports all user accounts, license assignments, MFA status, admin roles, and sign-in activity
- **02-Export-SharePoint.ps1** - Audits SharePoint sites, storage usage, permissions, sharing settings, and external access configurations
- **03-Export-SharedMailboxes.ps1** - Documents shared mailboxes with Full Access, Send As, and Send on Behalf permissions
- **04-Export-Groups.ps1** - Exports Microsoft 365 Groups, Teams, Distribution Lists, and Mail-Enabled Security Groups with membership details
- **05-Export-OrphanedResources.ps1** - Identifies Teams, Groups, and Shared Mailboxes without owners, plus inactive resources
- **06-Export-SecurityHygiene.ps1** - Analyzes MFA enrollment, legacy authentication usage, Conditional Access policies, password policies, and inactive user accounts
- **07-Export-PermissionSprawl.ps1** - Audits SharePoint external sharing, anonymous links, external users, and overly permissive configurations
- **08-Export-EmailHygiene.ps1** - Reviews mailbox forwarding rules, auto-forwarding settings, and suspicious inbox rules
- **09-Export-ThirdPartyApps.ps1** - Documents OAuth consent grants, service principals, and high-risk third-party app permissions
- **10-Export-Devices.ps1** - Exports managed device inventory, compliance status, and mobile device management configuration
- **11-Export-AuditLogging.ps1** - Checks Unified Audit Log status, mailbox auditing, and retention policies

### Optional Scripts
- **12-Check-DNSHealth.ps1** - Validates DNS records for SPF, DKIM, DMARC, and other email authentication configurations

---

## Quick Start Guide

### Prerequisites
- PowerShell 5.1 or later
- Administrator access to Microsoft 365 tenant
- Internet connection

### First-Time Setup
```powershell
# 1. Run troubleshooting script to verify setup
.\Troubleshoot-Setup.ps1

# 2. Register PnP PowerShell app (one-time setup)
.\00a-Register-PnP-App.ps1 -TenantDomain "yourcompany.onmicrosoft.com"

# 3. Connect to Microsoft 365 services
.\00-Connect-M365.ps1
```

### Running the Audit
```powershell
# Run scripts in order (01 through 11)
.\01-Export-Users.ps1
.\02-Export-SharePoint.ps1
.\03-Export-SharedMailboxes.ps1
.\04-Export-Groups.ps1
.\05-Export-OrphanedResources.ps1
.\06-Export-SecurityHygiene.ps1
.\07-Export-PermissionSprawl.ps1
.\08-Export-EmailHygiene.ps1
.\09-Export-ThirdPartyApps.ps1
.\10-Export-Devices.ps1
.\11-Export-AuditLogging.ps1

# Optional: Check DNS health
.\12-Check-DNSHealth.ps1
```

---

## Script Descriptions

### Setup & Connection Scripts

#### `Troubleshoot-Setup.ps1`
**Purpose:** Initial setup verification and troubleshooting

**What it does:**
- Checks PowerShell version compatibility (requires 5.1+)
- Verifies execution policy settings
- Unblocks all PowerShell scripts in the folder
- Checks if required modules are installed
- Tests basic connectivity to Microsoft 365

**When to use:**
- First time running the audit scripts
- Experiencing errors with blocked scripts
- Verifying your environment is properly configured

**No parameters required**

---

#### `00a-Register-PnP-App.ps1`
**Purpose:** Register custom Azure AD application for PnP PowerShell authentication

**What it does:**
- Registers a new Azure AD (Entra ID) application in your tenant
- Configures appropriate permissions for SharePoint access
- Generates a Client ID for use with PnP PowerShell
- Optionally sets the Client ID as an environment variable

**Why it's needed:**
As of September 2024, Microsoft deprecated the default PnP Management Shell app, so each tenant must register their own application.

**Parameters:**
- `TenantDomain` (required): Your Microsoft 365 domain (e.g., yourcompany.onmicrosoft.com)
- `ApplicationName` (optional): Custom name for the app (default: "M365 Audit - PnP PowerShell")
- `SetEnvironmentVariable` (switch): Automatically set ENTRAID_CLIENT_ID environment variable

**Example:**
```powershell
.\00a-Register-PnP-App.ps1 -TenantDomain "yourcompany.onmicrosoft.com" -SetEnvironmentVariable
```

**Run once:** This only needs to be run one time per tenant

---

#### `00-Connect-M365.ps1`
**Purpose:** Establish connections to all Microsoft 365 services

**What it does:**
- Connects to Microsoft Graph (for Azure AD, users, groups)
- Connects to Exchange Online (for mailboxes, mail flow)
- Connects to SharePoint Online (for sites, files, sharing)
- Connects to Microsoft Teams (for Teams data)
- Auto-detects tenant configuration
- Verifies successful connection to each service

**Authentication Methods:**
- Interactive (default): Browser-based login
- App-only: Certificate-based authentication for automation

**Parameters:**
- `UseInteractive` (default: $true): Use browser-based authentication
- `TenantId` (optional): Azure AD Tenant ID
- `SharePointAdminUrl` (optional): SharePoint admin URL (auto-detected if not provided)
- `CertificateThumbprint` (optional): For app-only auth
- `ApplicationId` (optional): For app-only auth

**Example:**
```powershell
# Interactive authentication (recommended for first run)
.\00-Connect-M365.ps1

# With specific SharePoint admin URL
.\00-Connect-M365.ps1 -SharePointAdminUrl "https://yourcompany-admin.sharepoint.com"
```

**Run first:** This must be run before any audit scripts

---

#### `simple-connect.ps1`
**Purpose:** Quick connection test for Microsoft Graph

**What it does:**
- Tests basic Microsoft Graph connectivity
- Automatically installs Microsoft.Graph module if missing
- Minimal connection test with User.Read.All scope

**When to use:**
- Testing if Microsoft Graph module works
- Troubleshooting connection issues
- Quick verification before running full audits

**No parameters required**

---

### Audit Scripts (Run in Order)

#### `01-Export-Users.ps1`
**Purpose:** Export comprehensive user and licensing data

**What it collects:**
- **User accounts:** Display name, UPN, email addresses, account status
- **License assignments:** Which users have which licenses, SKU details
- **MFA status:** Multi-factor authentication enrollment and methods
- **Admin role assignments:** Who has privileged access
- **Sign-in activity:** Last sign-in dates, sign-in frequency
- **Account types:** Guest vs. member users
- **Authentication details:** Enabled/disabled accounts

**Output files:**
- `Users.csv` - All user account details
- `AdminRoles.csv` - Administrative role assignments
- `Licenses.csv` - License SKU information and consumption
- `Summary.txt` - High-level statistics and findings

**Key findings it identifies:**
- Users without MFA enabled
- Unlicensed active users
- Inactive admin accounts
- License waste (disabled accounts with licenses)
- Guest user access

**Parameters:**
- `OutputPath` (optional): Custom output directory (default: ../Data/[timestamp]/)

**Example:**
```powershell
.\01-Export-Users.ps1
.\01-Export-Users.ps1 -OutputPath "C:\Audit\Users"
```

---

#### `02-Export-SharePoint.ps1`
**Purpose:** Export SharePoint Online sites, storage, and permissions

**What it collects:**
- **Site collections:** All Team sites, Communication sites, OneDrive
- **Storage metrics:** Usage, quotas, total consumption
- **Site ownership:** Primary admins and site collection administrators
- **Sharing settings:** External access configuration per site
- **Activity data:** Last activity dates, active vs. inactive sites
- **Site templates:** Types of sites in use
- **Hub associations:** Hub site relationships
- **Tenant settings:** Organization-wide sharing policies

**Output files:**
- `SharePointSites.csv` - All site collection details
- `SharePointTenant.csv` - Tenant-level configuration
- `SharePointStats.csv` - Storage and usage statistics
- `SharePointSummary.txt` - Summary and recommendations

**Key findings it identifies:**
- Sites approaching storage limits
- Inactive or abandoned sites
- Overly permissive sharing settings
- Sites without sensitivity labels
- External sharing risks

**Parameters:**
- `OutputPath` (optional): Custom output directory
- `IncludeOneDrive` (default: $true): Include OneDrive for Business sites

**Example:**
```powershell
.\02-Export-SharePoint.ps1
.\02-Export-SharePoint.ps1 -IncludeOneDrive:$false
```

---

#### `03-Export-SharedMailboxes.ps1`
**Purpose:** Export shared mailbox data and permissions

**What it collects:**
- **Mailbox details:** Name, email addresses, aliases
- **Storage information:** Mailbox size, quota, item counts
- **Permissions:** Full Access, Send As, Send on Behalf delegations
- **Configuration:** Auto-reply settings, forwarding rules
- **Usage statistics:** Last logon times, activity patterns
- **Delegates:** Who has access to each mailbox

**Output files:**
- `SharedMailboxes.csv` - All shared mailbox details
- `SharedMailboxes_FullAccess.csv` - Full Access permission grants
- `SharedMailboxes_SendAs.csv` - Send As permission grants
- `SharedMailboxes_SendOnBehalf.csv` - Send on Behalf delegations
- `SharedMailboxesSummary.txt` - Summary and findings

**Key findings it identifies:**
- Inactive shared mailboxes (>90 days)
- Excessive permissions (too many delegates)
- Mailboxes hidden from address lists
- Auto-forwarding enabled
- Large mailboxes needing archival
- Orphaned mailboxes without delegates

**Parameters:**
- `OutputPath` (optional): Custom output directory

**Example:**
```powershell
.\03-Export-SharedMailboxes.ps1
```

---

#### `04-Export-Groups.ps1`
**Purpose:** Export all Microsoft 365 groups and distribution lists

**What it collects:**
- **Microsoft 365 Groups (Unified Groups):** Modern collaboration groups
- **Distribution Lists:** Email distribution groups
- **Security Groups:** Azure AD security groups
- **Mail-Enabled Security Groups:** Hybrid security/distribution groups
- **Dynamic groups:** Auto-membership based on rules
- **Group ownership:** Owners and co-owners
- **Membership:** All group members
- **Configuration:** Privacy settings, external access, Teams connectivity

**Output files:**
- `Groups_Microsoft365.csv` - All M365 group details
- `Groups_Memberships.csv` - All group membership records
- `GroupsSummary.txt` - Summary and recommendations

**Key findings it identifies:**
- Groups without owners
- Empty groups
- Groups with external senders enabled
- Overly large groups
- Private vs. public group distribution
- Teams-connected groups

**Parameters:**
- `OutputPath` (optional): Custom output directory

**Example:**
```powershell
.\04-Export-Groups.ps1
```

---

#### `05-Export-OrphanedResources.ps1`
**Purpose:** Identify orphaned and inactive resources

**What it collects:**
- **Orphaned Groups:** Microsoft 365 Groups without owners
- **Orphaned Teams:** Teams without assigned owners
- **Orphaned Mailboxes:** Shared mailboxes without delegates
- **Inactive Users:** Accounts not used in X days
- **Inactive Groups:** M365 Groups with no activity
- **Inactive Teams:** Teams with no recent activity
- **Inactive Mailboxes:** Shared mailboxes not accessed recently

**Output files:**
- `OrphanedGroups.csv` - Groups without owners
- `OrphanedTeams.csv` - Teams without owners
- `OrphanedSharedMailboxes.csv` - Mailboxes without delegates
- `InactiveUsers.csv` - Inactive user accounts
- `InactiveM365Groups.csv` - Inactive groups
- `InactiveTeams.csv` - Inactive Teams
- `InactiveSharedMailboxes.csv` - Inactive mailboxes
- `OrphanedInactive-Summary.txt` - Summary report

**Key findings it identifies:**
- Resources without accountability/ownership
- Wasted licenses on inactive resources
- Data sprawl from forgotten resources
- Governance gaps
- Former employee data retention issues

**Parameters:**
- `OutputFolder` (optional): Custom output directory
- `InactiveDays` (default: 90): Threshold for considering resources inactive

**Example:**
```powershell
.\05-Export-OrphanedResources.ps1
.\05-Export-OrphanedResources.ps1 -InactiveDays 60
```

**Critical for:** Organizations that grew organically without formal IT management

---

#### `06-Export-SecurityHygiene.ps1`
**Purpose:** Identify authentication weaknesses, security gaps, and inactive accounts

**What it collects:**
- **MFA Status:** Multi-factor authentication enrollment
- **Authentication methods:** Registered MFA methods per user
- **Legacy protocols:** POP, IMAP, SMTP AUTH usage
- **Privileged accounts:** Admin accounts and their security posture
- **Conditional Access policies:** Policy configuration and coverage
- **Password policies:** Password expiration and complexity settings
- **Admin accounts:** Global Admins and privileged role holders
- **Inactive user accounts:** Accounts with no sign-in activity for 30+ days

**Output files:**
- `LegacyAuthProtocols.csv` - Mailboxes using legacy authentication
- `MFAStatus.csv` - MFA enrollment status per user
- `PrivilegedAccounts.csv` - Admin accounts security review
- `ConditionalAccessPolicies.csv` - CA policy configuration
- `PasswordPolicy.csv` - Password policy settings
- `InactiveAccounts.csv` - Inactive user accounts with risk assessment
- `SecurityHygiene-Summary.txt` - Critical findings and recommendations

**Key findings it identifies:**
- Users without MFA protection
- Admin accounts without MFA
- Legacy authentication usage (security bypass)
- Missing or disabled Conditional Access policies
- Weak password policies
- Excessive Global Administrators
- Inactive accounts with licenses (wasted costs)
- Inactive enabled accounts (security risk)
- Accounts that never signed in

**Parameters:**
- `OutputFolder` (optional): Custom output directory
- `InactiveDaysThreshold` (optional, default: 30): Number of days without sign-in to consider an account inactive

**Example:**
```powershell
.\06-Export-SecurityHygiene.ps1

# Check for accounts inactive for 90+ days instead of 30
.\06-Export-SecurityHygiene.ps1 -InactiveDaysThreshold 90
```

**Critical for:** Organizations without formal security policies

---

#### `07-Export-PermissionSprawl.ps1`
**Purpose:** Identify external sharing risks and permission sprawl

**What it collects:**
- **Guest users:** External users with tenant access
- **Guest domains:** Which external organizations have access
- **SharePoint sharing:** Site-level external sharing configuration
- **Anonymous links:** Sites allowing "Anyone with link" access
- **External user assignments:** Where guests have access
- **Publicly visible groups:** Groups visible to everyone
- **Tenant sharing settings:** Organization-wide sharing policies
- **Overly permissive groups:** Groups with excessive access

**Output files:**
- `GuestUsers.csv` - All guest user accounts
- `GuestUsersByDomain.csv` - Guest users grouped by domain
- `SharePointSiteSharing.csv` - Sharing settings per site
- `SitesWithExternalUsers.csv` - Sites with guest access
- `OverlyPermissiveGroups.csv` - Groups with broad access
- `TenantSharingSettings.csv` - Tenant-level sharing configuration
- `PermissionSprawl-Summary.txt` - Risk assessment and recommendations

**Key findings it identifies:**
- Anonymous sharing links (anyone with link)
- Sites with external user access
- Missing domain restrictions for sharing
- No expiration on guest access
- External users who can reshare content
- Publicly visible groups
- Missing sensitivity labels

**Parameters:**
- `OutputFolder` (optional): Custom output directory

**Example:**
```powershell
.\07-Export-PermissionSprawl.ps1
```

**Critical for:** Organizations without formal data governance

---

#### `08-Export-EmailHygiene.ps1`
**Purpose:** Identify email security and compliance issues

**What it collects:**
- **Auto-forwarding rules:** Mailboxes forwarding to external addresses
- **Inbox rules:** Suspicious or malicious email rules
- **Mailbox delegations:** Delegate permissions granted
- **Retention policies:** Email retention and compliance policies
- **Mailboxes without retention:** Compliance gaps
- **Mailbox auditing:** Audit log status per mailbox
- **Litigation holds:** Mailboxes on legal hold
- **Compliance status:** Overall email compliance posture

**Output files:**
- `AutoForwardingMailboxes.csv` - Mailboxes with external forwarding
- `SuspiciousInboxRules.csv` - Potentially malicious inbox rules
- `MailboxDelegatePermissions.csv` - All delegate permissions
- `RetentionPolicies.csv` - Configured retention policies
- `MailboxesWithoutRetention.csv` - Mailboxes lacking retention
- `MailboxComplianceStatus.csv` - Compliance overview per mailbox
- `EmailHygiene-Summary.txt` - Critical findings

**Key findings it identifies:**
- External auto-forwarding (to personal email)
- Suspicious inbox rules (auto-delete, forwarding)
- Excessive delegate permissions
- Missing retention policies
- Disabled mailbox auditing
- Email forwarding to competitors/threats

**Parameters:**
- `OutputFolder` (optional): Custom output directory

**Example:**
```powershell
.\08-Export-EmailHygiene.ps1
```

**Critical for:** Organizations without formal email security policies

---

#### `09-Export-ThirdPartyApps.ps1`
**Purpose:** Identify third-party app risks and OAuth grants

**What it collects:**
- **OAuth consent grants:** Apps with access to organizational data
- **Service principals:** All registered service accounts
- **Application registrations:** Custom apps in Azure AD
- **Permission scopes:** What permissions each app has
- **Consent type:** User-level vs. organization-wide consents
- **High-risk permissions:** Apps with dangerous permissions
- **Apps without owners:** Orphaned applications
- **Expired credentials:** Apps with invalid credentials

**Output files:**
- `OAuthConsentGrants.csv` - All OAuth permission grants
- `ServicePrincipals.csv` - All service principal accounts
- `ApplicationRegistrations.csv` - Registered applications
- `HighRiskPermissionGrants.csv` - Apps with dangerous permissions
- `ThirdPartyApps-Summary.txt` - Risk assessment

**Key findings it identifies:**
- Apps with high-risk permissions (Mail.ReadWrite.All, Files.ReadWrite.All, etc.)
- Organization-wide consents (entire tenant access)
- Apps without assigned owners
- Expired or expiring credentials
- Unnecessary third-party access
- Shadow IT applications

**High-risk permissions flagged:**
- `Mail.ReadWrite.All` - Full mailbox access
- `Files.ReadWrite.All` - Access to all files
- `Directory.ReadWrite.All` - Modify directory data
- `User.ReadWrite.All` - Modify all users
- `RoleManagement.ReadWrite.Directory` - Assign admin roles

**Parameters:**
- `OutputFolder` (optional): Custom output directory

**Example:**
```powershell
.\09-Export-ThirdPartyApps.ps1
```

**Critical for:** Organizations without application governance

---

#### `10-Export-Devices.ps1`
**Purpose:** Export device inventory and management data

**What it collects:**
- **Azure AD registered devices:** All devices joined to Azure AD
- **Mobile devices:** ActiveSync mobile devices
- **Device compliance:** Compliance status (if MDM configured)
- **Stale devices:** Devices not used in X days
- **Device platforms:** Operating system breakdown
- **Device ownership:** Corporate vs. personal devices
- **Blocked/quarantined devices:** Devices with access issues

**Output files:**
- `AzureADDevices.csv` - All Azure AD registered devices
- `MobileDevices.csv` - Mobile device inventory (ActiveSync)
- `DevicesByOperatingSystem.csv` - Device platform statistics
- `DeviceInventory-Summary.txt` - Summary and recommendations

**Key findings it identifies:**
- Stale device registrations (>90 days inactive)
- Non-compliant devices (if MDM enabled)
- Blocked or quarantined mobile devices
- Unmanaged devices
- Device platform distribution
- Devices without recent activity

**Parameters:**
- `OutputFolder` (optional): Custom output directory
- `StaleDays` (default: 90): Threshold for stale devices

**Example:**
```powershell
.\10-Export-Devices.ps1
.\10-Export-Devices.ps1 -StaleDays 60
```

**Critical for:** Organizations without device management policies

---

#### `11-Export-AuditLogging.ps1`
**Purpose:** Check audit logging and monitoring configuration

**What it collects:**
- **Unified Audit Log status:** Whether audit logging is enabled (CRITICAL)
- **Admin audit log settings:** Admin action logging
- **Mailbox auditing:** Default and per-mailbox audit status
- **Alert policies:** Configured security alerts
- **Log retention:** How long logs are kept
- **Azure AD sign-in logs:** Configuration and retention
- **Diagnostic settings:** Log export and archival configuration

**Output files:**
- `UnifiedAuditLogConfig.csv` - Unified Audit Log status
- `OrganizationAuditConfig.csv` - Organization audit settings
- `MailboxAuditStatus-Sample.csv` - Sample of mailbox audit status
- `AzureADLoggingConfig.csv` - Azure AD logging configuration
- `AuditLogging-Summary.txt` - Critical compliance findings

**Key findings it identifies:**
- **CRITICAL:** Unified Audit Log disabled (compliance violation)
- Mailbox auditing disabled
- Missing alert policies
- Insufficient log retention
- No long-term log archival
- Compliance and forensic capability gaps

**Why this matters:**
- Required for eDiscovery and legal holds
- Necessary for security incident investigation
- Mandated by most compliance frameworks (GDPR, SOC 2, etc.)
- Enables insider threat detection
- Provides forensic audit trail

**Parameters:**
- `OutputFolder` (optional): Custom output directory

**Example:**
```powershell
.\11-Export-AuditLogging.ps1
```

**Most critical script** - Audit logging is foundation of compliance

---

### Optional/Utility Scripts

#### `12-Check-DNSHealth.ps1`
**Purpose:** Comprehensive DNS health check for Microsoft 365 domains

**What it checks:**
- **Basic resolution:** A and AAAA records
- **Mail routing:** MX records for email delivery
- **Email authentication:** SPF, DKIM, DMARC records
- **DNSSEC validation:** DNS security extensions
- **Health scoring:** Overall DNS configuration score
- **Microsoft 365 records:** Autodiscover, SIP, etc.

**Output files:**
- `DNS-Health-Report-[timestamp].csv` - Detailed DNS results

**Key findings it identifies:**
- Missing or incorrect MX records
- SPF configuration issues (email spoofing risk)
- Missing DKIM signatures
- Weak or missing DMARC policies
- DNSSEC validation failures
- Microsoft 365 DNS configuration errors

**Parameters:**
- `Domains` (optional): Specific domains to check (auto-detects if not provided)
- `OutputPath` (optional): Custom output file location
- `Detailed` (switch): Include detailed DNS record information

**Example:**
```powershell
# Auto-detect domains from M365 tenant
.\12-Check-DNSHealth.ps1

# Check specific domains
.\12-Check-DNSHealth.ps1 -Domains "contoso.com", "fabrikam.com"

# Detailed output
.\12-Check-DNSHealth.ps1 -Detailed -OutputPath "C:\Reports\DNS-Health.csv"
```

**When to use:**
- Email delivery issues
- Email authentication problems (spoofing)
- Domain migration or configuration changes
- Compliance verification for email security

---

## Output Structure

All scripts export data to a common folder structure:

```
Data/
└── 2025-11-05/  (timestamp folder)
    ├── Users.csv
    ├── AdminRoles.csv
    ├── Licenses.csv
    ├── Summary.txt
    ├── SharePointSites.csv
    ├── SharePointTenant.csv
    ├── ... (all other CSV and summary files)
```

**File Types:**
- **`.csv`** - Detailed data exports (open in Excel or PowerShell)
- **`.txt`** - Human-readable summary reports with findings and recommendations

---

## Required PowerShell Modules

The scripts automatically check for and can install these modules:

1. **Microsoft.Graph** - Azure AD, users, groups, devices, apps
   - `Install-Module -Name Microsoft.Graph -Scope CurrentUser`

2. **ExchangeOnlineManagement** - Exchange Online, mailboxes, mail flow
   - `Install-Module -Name ExchangeOnlineManagement -Scope CurrentUser`

3. **PnP.PowerShell** - SharePoint Online, sites, permissions
   - `Install-Module -Name PnP.PowerShell -Scope CurrentUser`

4. **MicrosoftTeams** - Microsoft Teams data
   - `Install-Module -Name MicrosoftTeams -Scope CurrentUser`

---

## Permissions Required

The account running these scripts needs:

**Minimum Required Roles:**
- **Global Reader** - Can read all data without making changes (recommended)
- **Security Reader** - Can read security configurations
- **Reports Reader** - Can read usage reports

**Alternative (higher privilege):**
- **Global Administrator** - Full access (more than needed, use with caution)

**Specific Permissions Needed:**
- Microsoft Graph: `User.Read.All`, `Group.Read.All`, `Application.Read.All`, `Directory.Read.All`
- Exchange Online: `View-Only Recipients`, `View-Only Configuration`
- SharePoint Online: Tenant admin or site collection admin
- Teams: Teams admin or Global Reader

---

## Best Practices

### Running the Audit

1. **Schedule regular audits:** Monthly or quarterly depending on organization size
2. **Run all scripts:** Complete picture requires all data points
3. **Compare over time:** Track improvements and new issues
4. **Document findings:** Keep records of discovered issues and remediation
5. **Run during off-hours:** Some scripts can be resource-intensive

### Security

1. **Use a dedicated audit account:** Don't use production admin accounts
2. **Enable MFA on audit account:** Protect the account running audits
3. **Store output securely:** Audit data contains sensitive information
4. **Limit access to results:** Only authorized personnel should review
5. **Delete old audit data:** Retain only what's needed for compliance

### Troubleshooting

If scripts fail to run:

1. **Run `Troubleshoot-Setup.ps1` first**
2. **Check execution policy:** May need to set to RemoteSigned
3. **Unblock scripts:** Right-click > Properties > Unblock
4. **Install modules:** Some modules may need manual installation
5. **Check permissions:** Ensure account has required roles
6. **Test connectivity:** Verify access to Microsoft 365 services

---

## Common Issues & Solutions

### "File is blocked" or "Cannot be loaded"
**Solution:** Run `Troubleshoot-Setup.ps1` or manually unblock:
```powershell
Get-ChildItem -Path .\Scripts\*.ps1 | Unblock-File
```

### "Module not found"
**Solution:** Install required module:
```powershell
Install-Module -Name Microsoft.Graph -Scope CurrentUser -Force
```

### "Access denied"
**Solution:** Verify account has required admin roles (Global Reader minimum)

### "Connection failed"
**Solution:**
1. Run `.\00-Connect-M365.ps1` first
2. Check internet connectivity
3. Verify credentials
4. Check for service outages at status.microsoft.com

### "PnP PowerShell not working"
**Solution:** Register your own PnP app:
```powershell
.\00a-Register-PnP-App.ps1 -TenantDomain "yourcompany.onmicrosoft.com"
```

---

## Script Execution Order

For a complete audit, run scripts in this order:

```powershell
# Setup (one-time)
.\Troubleshoot-Setup.ps1
.\00a-Register-PnP-App.ps1 -TenantDomain "yourcompany.onmicrosoft.com"

# Connect (every session)
.\00-Connect-M365.ps1

# Core audit (run all)
.\01-Export-Users.ps1
.\02-Export-SharePoint.ps1
.\03-Export-SharedMailboxes.ps1
.\04-Export-Groups.ps1
.\05-Export-OrphanedResources.ps1
.\06-Export-SecurityHygiene.ps1
.\07-Export-PermissionSprawl.ps1
.\08-Export-EmailHygiene.ps1
.\09-Export-ThirdPartyApps.ps1
.\10-Export-Devices.ps1
.\11-Export-AuditLogging.ps1

# Optional
.\12-Check-DNSHealth.ps1
```

**Total runtime:** Approximately 30-60 minutes depending on tenant size

---

## What Gets Audited

| Category | Script | What It Finds | Critical Issues |
|----------|--------|---------------|-----------------|
| **Users & Licensing** | 01-Export-Users.ps1 | Account status, MFA, licenses, admins | No MFA, unlicensed users, inactive admins |
| **SharePoint** | 02-Export-SharePoint.ps1 | Sites, storage, sharing settings | Anonymous sharing, storage limits, external access |
| **Email** | 03-Export-SharedMailboxes.ps1 | Shared mailboxes, permissions | Inactive mailboxes, excessive permissions |
| **Collaboration** | 04-Export-Groups.ps1 | All group types, membership | Groups without owners, empty groups |
| **Governance** | 05-Export-OrphanedResources.ps1 | Orphaned/inactive resources | No accountability, wasted licenses |
| **Authentication** | 06-Export-SecurityHygiene.ps1 | MFA, legacy auth, Conditional Access, inactive accounts | No MFA, legacy protocols enabled, no CA policies, inactive accounts with licenses |
| **Data Sharing** | 07-Export-PermissionSprawl.ps1 | External access, guest users, oversharing | Anonymous links, no domain restrictions |
| **Email Security** | 08-Export-EmailHygiene.ps1 | Forwarding, inbox rules, retention | External forwarding, suspicious rules |
| **Third-Party Apps** | 09-Export-ThirdPartyApps.ps1 | OAuth grants, app permissions | High-risk permissions, org-wide consents |
| **Devices** | 10-Export-Devices.ps1 | Device inventory, compliance | Stale devices, blocked devices, no MDM |
| **Compliance** | 11-Export-AuditLogging.ps1 | Audit log configuration | **CRITICAL:** Audit log disabled |
| **DNS** | 12-Check-DNSHealth.ps1 | DNS records, email auth | Missing SPF/DKIM/DMARC, MX issues |

---

## Understanding the Output

### CSV Files
- Open in Excel for analysis
- Use filters to find specific issues
- Sort by columns to identify patterns
- Pivot tables for aggregation

### Summary .txt Files
- Human-readable findings
- High-level statistics
- Critical issues highlighted with [CRITICAL], [WARNING], [OK], [INFO]
- Specific recommendations for remediation
- File references for detailed data

### Example Analysis Workflow
1. Read summary .txt files first for overview
2. Review [CRITICAL] and [WARNING] items
3. Open corresponding CSV files for details
4. Export filtered results for remediation tracking
5. Document findings in your audit report

---

## Data Retention

**Recommendation:**
- Keep audit results for at least 1 year for compliance
- Compare month-over-month to track improvements
- Archive old results after 2-3 years

**Sensitive Data:**
- Results contain PII and configuration details
- Store in secure, encrypted location
- Limit access to authorized personnel only
- Consider encrypting the Data folder

---

## Support & Updates

**For issues or questions:**
1. Check this documentation first
2. Run `Troubleshoot-Setup.ps1` to verify environment
3. Review error messages carefully
4. Check PowerShell version and module versions

**Updating the scripts:**
- Download latest versions from repository
- Review changelog for breaking changes
- Test in non-production tenant first
- Re-run `00a-Register-PnP-App.ps1` if PnP authentication changes

---

## Conclusion

These scripts provide comprehensive visibility into your Microsoft 365 environment's security posture, compliance status, and governance practices. Regular execution helps identify issues before they become security incidents or compliance violations.

**Key Takeaways:**
- Run `00-Connect-M365.ps1` first every time
- Run scripts 01-11 in order for complete audit
- Review summary .txt files for quick insights
- Address [CRITICAL] findings immediately
- Schedule regular audits (monthly/quarterly)
- Track improvements over time

---

*Last Updated: November 5, 2025*
*Script Version: 1.0*
*Documentation Version: 1.0*
