<#
.SYNOPSIS
    Export audit logging and monitoring configuration from M365.

.DESCRIPTION
    This script checks audit log status, alert policies, and monitoring
    configuration. Critical for ensuring compliance and security visibility.

.PARAMETER OutputFolder
    Folder path for exported data. Defaults to ..\Data\[timestamp]

.EXAMPLE
    .\11-Export-AuditLogging.ps1
    Export audit logging configuration.

.NOTES
    Author: IT Audit
    Date: 2025-11-05
    
    Prerequisites:
    - Run 00-Connect-M365.ps1 first to establish connections
    - Requires Microsoft.Graph, ExchangeOnlineManagement modules
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$OutputFolder
)

$ErrorActionPreference = "Continue"

# Create timestamp for this run
$timestamp = Get-Date -Format "yyyy-MM-dd"

# Set output folder if not specified
if ([string]::IsNullOrEmpty($OutputFolder)) {
    $scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
    $OutputFolder = Join-Path (Split-Path -Parent $scriptPath) "Data\$timestamp"
}

# Create output folder if it doesn't exist
if (-not (Test-Path $OutputFolder)) {
    New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null
}

Write-Host "=============================================================" -ForegroundColor Cyan
Write-Host "     Audit Logging & Monitoring Export                     " -ForegroundColor Cyan
Write-Host "     IT Audit Toolkit                                      " -ForegroundColor Cyan
Write-Host "=============================================================" -ForegroundColor Cyan

Write-Host "`nOutput folder: $OutputFolder" -ForegroundColor Yellow
Write-Host ""

#region Unified Audit Log Configuration
Write-Host "[1/5] Checking Unified Audit Log configuration..." -ForegroundColor Yellow

try {
    $auditConfig = Get-AdminAuditLogConfig
    
    $auditLogStatus = [PSCustomObject]@{
        UnifiedAuditLogIngestionEnabled = $auditConfig.UnifiedAuditLogIngestionEnabled
        LogLevel = $auditConfig.LogLevel
        AdminAuditLogEnabled = $auditConfig.AdminAuditLogEnabled
        AdminAuditLogAgeLimit = $auditConfig.AdminAuditLogAgeLimit
        AdminAuditLogCmdlets = ($auditConfig.AdminAuditLogCmdlets -join '; ')
    }
    
    $auditLogStatus | Export-Csv -Path (Join-Path $OutputFolder "UnifiedAuditLogConfig.csv") -NoTypeInformation
    
    if ($auditConfig.UnifiedAuditLogIngestionEnabled) {
        Write-Host "  [OK] Unified Audit Log is ENABLED" -ForegroundColor Green
    } else {
        Write-Host "  [X] Unified Audit Log is DISABLED" -ForegroundColor Red
    }
} catch {
    Write-Warning "Failed to check Unified Audit Log: $_"
}
#endregion

#region Mailbox Auditing
Write-Host "[2/5] Checking mailbox auditing configuration..." -ForegroundColor Yellow

try {
    # Get organization config for mailbox auditing
    $orgConfig = Get-OrganizationConfig
    
    $orgAuditConfig = [PSCustomObject]@{
        AuditDisabled = $orgConfig.AuditDisabled
        DefaultAuditSet = if ($orgConfig.AuditDisabled) { "Disabled" } else { "Enabled by default" }
    }
    
    $orgAuditConfig | Export-Csv -Path (Join-Path $OutputFolder "OrganizationAuditConfig.csv") -NoTypeInformation
    
    # Sample mailbox audit status (first 100)
    $mailboxes = Get-Mailbox -ResultSize 100
    $auditStatus = @()
    
    foreach ($mailbox in $mailboxes) {
        $auditStatus += [PSCustomObject]@{
            DisplayName = $mailbox.DisplayName
            UserPrincipalName = $mailbox.UserPrincipalName
            AuditEnabled = $mailbox.AuditEnabled
            AuditOwner = ($mailbox.AuditOwner -join ', ')
            AuditDelegate = ($mailbox.AuditDelegate -join ', ')
            AuditAdmin = ($mailbox.AuditAdmin -join ', ')
            Issue = if (-not $mailbox.AuditEnabled) { "Auditing disabled" } else { "" }
        }
    }
    
    $auditStatus | Export-Csv -Path (Join-Path $OutputFolder "MailboxAuditStatus-Sample.csv") -NoTypeInformation
    
    $disabledAudit = ($auditStatus | Where-Object { -not $_.AuditEnabled }).Count
    
    if ($orgConfig.AuditDisabled) {
        Write-Host "  [X] Mailbox auditing is DISABLED by default" -ForegroundColor Red
    } else {
        Write-Host "  [OK] Mailbox auditing is enabled by default" -ForegroundColor Green
    }
    Write-Host "    - Sample: $disabledAudit of 100 mailboxes have auditing disabled" -ForegroundColor $(if($disabledAudit -gt 0){'Yellow'}else{'Green'})
} catch {
    Write-Warning "Failed to check mailbox auditing: $_"
}
#endregion

#region Alert Policies
Write-Host "[3/5] Exporting alert policies..." -ForegroundColor Yellow

try {
    $alertPolicies = Get-ProtectionAlert
    
    $alertReport = $alertPolicies | Select-Object @{
        Name = "Name"
        Expression = { $_.Name }
    }, @{
        Name = "Severity"
        Expression = { $_.Severity }
    }, @{
        Name = "Category"
        Expression = { $_.Category }
    }, @{
        Name = "Disabled"
        Expression = { $_.Disabled }
    }, @{
        Name = "NotifyUser"
        Expression = { ($_.NotifyUser -join '; ') }
    }, @{
        Name = "Description"
        Expression = { $_.Comment }
    }
    
    $alertReport | Export-Csv -Path (Join-Path $OutputFolder "AlertPolicies.csv") -NoTypeInformation
    
    $enabledAlerts = ($alertPolicies | Where-Object { -not $_.Disabled }).Count
    $disabledAlerts = ($alertPolicies | Where-Object { $_.Disabled }).Count
    
    Write-Host "  [OK] Found $($alertPolicies.Count) alert policies" -ForegroundColor Cyan
    Write-Host "    - Enabled: $enabledAlerts" -ForegroundColor Green
    Write-Host "    - Disabled: $disabledAlerts" -ForegroundColor $(if($disabledAlerts -gt 0){'Yellow'}else{'Green'})
} catch {
    Write-Warning "Failed to export alert policies: $_"
}
#endregion

#region Azure AD Sign-in Logs Configuration
Write-Host "[4/5] Checking Azure AD diagnostic settings..." -ForegroundColor Yellow

try {
    # Get organization configuration
    $org = Get-MgOrganization
    
    $diagSettings = [PSCustomObject]@{
        TenantId = $org.Id
        DisplayName = $org.DisplayName
        Note = "Sign-in logs retained for 30 days in Azure AD Free/P1, 7 days in Basic"
        Recommendation = "Configure diagnostic settings to export logs to Log Analytics or Storage Account for long-term retention"
    }
    
    $diagSettings | Export-Csv -Path (Join-Path $OutputFolder "AzureADLoggingConfig.csv") -NoTypeInformation
    Write-Host "  [OK] Azure AD logging configuration exported" -ForegroundColor Yellow
    Write-Host "    Note: Configure diagnostic settings for long-term log retention" -ForegroundColor Yellow
} catch {
    Write-Warning "Failed to check Azure AD logging: $_"
}
#endregion

#region Summary Report
Write-Host "[5/5] Generating audit logging summary..." -ForegroundColor Yellow

$criticalIssues = @()

if (-not $auditConfig.UnifiedAuditLogIngestionEnabled) {
    $criticalIssues += "[CRITICAL] CRITICAL: Unified Audit Log is DISABLED - this is a serious compliance and security gap"
}

if ($orgConfig.AuditDisabled) {
    $criticalIssues += "[CRITICAL] CRITICAL: Mailbox auditing is DISABLED by default"
}

if ($disabledAudit -gt 10) {
    $criticalIssues += "[WARNING]  $disabledAudit sampled mailboxes have auditing disabled"
}

if ($disabledAlerts -gt ($alertPolicies.Count * 0.5)) {
    $criticalIssues += "[WARNING]  More than 50% of alert policies are disabled"
}

$summary = @"
Audit Logging & Monitoring Configuration Report
Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")

UNIFIED AUDIT LOG:
- Status: $(if($auditConfig.UnifiedAuditLogIngestionEnabled){"[OK] ENABLED"}else{"[X] DISABLED"})
- Admin Audit Log Enabled: $(if($auditConfig.AdminAuditLogEnabled){"Yes"}else{"No"})
- Log Age Limit: $($auditConfig.AdminAuditLogAgeLimit)

MAILBOX AUDITING:
- Organization Default: $(if($orgConfig.AuditDisabled){"DISABLED"}else{"ENABLED"})
- Sample (100 mailboxes) with auditing disabled: $disabledAudit

ALERT POLICIES:
- Total policies: $($alertPolicies.Count)
- Enabled policies: $enabledAlerts
- Disabled policies: $disabledAlerts

AZURE AD SIGN-IN LOGS:
- Default retention: 30 days (Premium) / 7 days (Free/Basic)
- Recommendation: Configure diagnostic settings for long-term retention

CRITICAL FINDINGS:
$(if($criticalIssues.Count -gt 0){$criticalIssues -join "`n"}else{"No critical issues found"})

COMPLIANCE IMPACT:
- Unified Audit Log is REQUIRED for:
  * eDiscovery and legal holds
  * Security investigations
  * Compliance audits
  * Insider risk management
  
- Mailbox Auditing is REQUIRED for:
  * Investigating mailbox access
  * Compliance with data protection regulations
  * Forensic analysis of email activity

RECOMMENDATIONS:
1. CRITICAL: Enable Unified Audit Log if disabled
2. CRITICAL: Enable mailbox auditing by default if disabled
3. HIGH: Configure Azure AD diagnostic settings to export logs to:
   - Log Analytics workspace (for queries and alerts)
   - Storage Account (for long-term archival)
4. HIGH: Review and enable critical alert policies
5. MEDIUM: Ensure key personnel are configured as alert recipients
6. MEDIUM: Regular review of audit logs (weekly for security events)
7. LOW: Document audit log retention policies for compliance

ALERT POLICIES TO ENABLE (if disabled):
- Elevation of Exchange admin privilege
- Suspicious email forwarding activity
- Unusual increase in email reported as phish
- User clicked through to malicious URL
- Files detected containing malware
- Suspicious inbox manipulation rules

LONG-TERM LOG RETENTION:
- Unified Audit Log: 90 days (default), up to 1 year or 10 years with add-on
- Configure export to Log Analytics or Storage Account for retention beyond defaults
- Recommend: 1-7 years retention based on compliance requirements

"@

$summary | Out-File -FilePath (Join-Path $OutputFolder "AuditLogging-Summary.txt") -Encoding UTF8
Write-Host "  [OK] Audit logging summary generated" -ForegroundColor Green

Write-Host "`n" + ("="*60) -ForegroundColor Cyan
if ($criticalIssues.Count -gt 0) {
    Write-Host "[CRITICAL] CRITICAL AUDIT LOGGING ISSUES FOUND!" -ForegroundColor Red
    Write-Host "`nCritical Issues:" -ForegroundColor Red
    foreach ($issue in $criticalIssues) {
        Write-Host "  $issue" -ForegroundColor Red
    }
} else {
    Write-Host "Audit Logging Export Complete!" -ForegroundColor Green
}
Write-Host ("="*60) -ForegroundColor Cyan
Write-Host "`nResults saved to: $OutputFolder" -ForegroundColor Cyan
Write-Host ""
#endregion

