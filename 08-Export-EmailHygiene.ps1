<#
.SYNOPSIS
    Export email hygiene and compliance data from Exchange Online.

.DESCRIPTION
    This script identifies email forwarding rules, suspicious configurations,
    retention policy gaps, and compliance issues. Critical for organizations
    without formal email security policies.

.PARAMETER OutputFolder
    Folder path for exported data. Defaults to ..\Data\[timestamp]

.EXAMPLE
    .\08-Export-EmailHygiene.ps1
    Export email hygiene data with default settings.

.NOTES
    Author: IT Audit
    Date: 2025-11-05
    
    Prerequisites:
    - Run 00-Connect-M365.ps1 first to establish connections
    - Requires ExchangeOnlineManagement module
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
Write-Host "     Email Hygiene & Compliance Export                     " -ForegroundColor Cyan
Write-Host "     IT Audit Toolkit                                      " -ForegroundColor Cyan
Write-Host "=============================================================" -ForegroundColor Cyan

Write-Host "`nOutput folder: $OutputFolder" -ForegroundColor Yellow
Write-Host ""

#region Auto-Forwarding Rules
Write-Host "[1/6] Checking auto-forwarding configurations..." -ForegroundColor Yellow

try {
    $mailboxes = Get-Mailbox -ResultSize Unlimited
    $forwardingMailboxes = @()
    
    $mbxCount = 0
    foreach ($mailbox in $mailboxes) {
        $mbxCount++
        Write-Progress -Activity "Checking forwarding rules" -Status "$mbxCount of $($mailboxes.Count)" -PercentComplete (($mbxCount / $mailboxes.Count) * 100)
        
        # Check mailbox-level forwarding
        if ($mailbox.ForwardingAddress -or $mailbox.ForwardingSMTPAddress) {
            $forwardingMailboxes += [PSCustomObject]@{
                DisplayName = $mailbox.DisplayName
                UserPrincipalName = $mailbox.UserPrincipalName
                ForwardingType = "Mailbox-level"
                ForwardingAddress = if ($mailbox.ForwardingAddress) { $mailbox.ForwardingAddress } else { $mailbox.ForwardingSMTPAddress }
                DeliverToMailboxAndForward = $mailbox.DeliverToMailboxAndForward
                RecipientType = $mailbox.RecipientTypeDetails
                Issue = if ($mailbox.ForwardingSMTPAddress -like "*@gmail.com" -or $mailbox.ForwardingSMTPAddress -like "*@yahoo.com" -or $mailbox.ForwardingSMTPAddress -like "*@outlook.com") { "Forwarding to personal email" } else { "External forwarding" }
            }
        }
    }
    
    $forwardingMailboxes | Export-Csv -Path (Join-Path $OutputFolder "AutoForwardingMailboxes.csv") -NoTypeInformation
    
    $externalForwarding = ($forwardingMailboxes | Where-Object { $_.ForwardingAddress -notlike "*@*onmicrosoft.com" }).Count
    Write-Host "  [OK] Found $($forwardingMailboxes.Count) mailboxes with auto-forwarding" -ForegroundColor $(if($forwardingMailboxes.Count -gt 0){'Red'}else{'Green'})
    if ($externalForwarding -gt 0) {
        Write-Host "    [CRITICAL] $externalForwarding forwarding to external addresses" -ForegroundColor Red
    }
} catch {
    Write-Warning "Failed to check auto-forwarding: $_"
}
#endregion

#region Inbox Rules
Write-Host "[2/6] Checking suspicious inbox rules..." -ForegroundColor Yellow

try {
    $suspiciousRules = @()
    
    $mbxCount = 0
    foreach ($mailbox in $mailboxes | Select-Object -First 100) { # Limit for performance
        $mbxCount++
        Write-Progress -Activity "Checking inbox rules" -Status "$mbxCount of 100" -PercentComplete (($mbxCount / 100) * 100)
        
        try {
            $inboxRules = Get-InboxRule -Mailbox $mailbox.UserPrincipalName -ErrorAction SilentlyContinue
            
            foreach ($rule in $inboxRules) {
                # Check for forwarding or redirecting rules
                if ($rule.ForwardTo -or $rule.ForwardAsAttachmentTo -or $rule.RedirectTo) {
                    $suspiciousRules += [PSCustomObject]@{
                        Mailbox = $mailbox.DisplayName
                        UserPrincipalName = $mailbox.UserPrincipalName
                        RuleName = $rule.Name
                        Enabled = $rule.Enabled
                        ForwardTo = ($rule.ForwardTo -join '; ')
                        RedirectTo = ($rule.RedirectTo -join '; ')
                        DeleteMessage = $rule.DeleteMessage
                        Issue = "Forwarding/Redirect rule"
                    }
                }
                # Check for rules that delete messages
                elseif ($rule.DeleteMessage -eq $true -and $rule.MoveToFolder -eq $null) {
                    $suspiciousRules += [PSCustomObject]@{
                        Mailbox = $mailbox.DisplayName
                        UserPrincipalName = $mailbox.UserPrincipalName
                        RuleName = $rule.Name
                        Enabled = $rule.Enabled
                        ForwardTo = ""
                        RedirectTo = ""
                        DeleteMessage = $rule.DeleteMessage
                        Issue = "Auto-delete rule"
                    }
                }
            }
        } catch {
            # Silent continue
        }
    }
    
    $suspiciousRules | Export-Csv -Path (Join-Path $OutputFolder "SuspiciousInboxRules.csv") -NoTypeInformation
    Write-Host "  [OK] Found $($suspiciousRules.Count) suspicious inbox rules" -ForegroundColor $(if($suspiciousRules.Count -gt 0){'Yellow'}else{'Green'})
} catch {
    Write-Warning "Failed to check inbox rules: $_"
}
#endregion

#region Mailbox Permissions
Write-Host "[3/6] Checking mailbox delegate permissions..." -ForegroundColor Yellow

try {
    $delegatePermissions = @()
    
    $mbxCount = 0
    foreach ($mailbox in $mailboxes | Select-Object -First 100) { # Limit for performance
        $mbxCount++
        Write-Progress -Activity "Checking mailbox permissions" -Status "$mbxCount of 100" -PercentComplete (($mbxCount / 100) * 100)
        
        try {
            # Check Full Access permissions
            $fullAccessPerms = Get-MailboxPermission -Identity $mailbox.Identity | Where-Object {
                $_.User -ne "NT AUTHORITY\SELF" -and 
                $_.User -notlike "S-1-5-*" -and
                $_.IsInherited -eq $false -and
                $_.AccessRights -contains "FullAccess"
            }
            
            foreach ($perm in $fullAccessPerms) {
                $delegatePermissions += [PSCustomObject]@{
                    Mailbox = $mailbox.DisplayName
                    MailboxUPN = $mailbox.UserPrincipalName
                    Delegate = $perm.User
                    PermissionType = "Full Access"
                    AccessRights = ($perm.AccessRights -join ', ')
                    Issue = if ($perm.User -like "*#EXT#*") { "External user has full access" } else { "" }
                }
            }
            
            # Check Send As permissions
            $sendAsPerms = Get-RecipientPermission -Identity $mailbox.Identity | Where-Object {
                $_.Trustee -ne "NT AUTHORITY\SELF" -and
                $_.AccessRights -contains "SendAs"
            }
            
            foreach ($perm in $sendAsPerms) {
                $delegatePermissions += [PSCustomObject]@{
                    Mailbox = $mailbox.DisplayName
                    MailboxUPN = $mailbox.UserPrincipalName
                    Delegate = $perm.Trustee
                    PermissionType = "Send As"
                    AccessRights = ($perm.AccessRights -join ', ')
                    Issue = if ($perm.Trustee -like "*#EXT#*") { "External user has send as" } else { "" }
                }
            }
        } catch {
            # Silent continue
        }
    }
    
    $delegatePermissions | Export-Csv -Path (Join-Path $OutputFolder "MailboxDelegatePermissions.csv") -NoTypeInformation
    
    $externalDelegates = ($delegatePermissions | Where-Object { $_.Issue -ne "" }).Count
    Write-Host "  [OK] Found $($delegatePermissions.Count) mailbox delegations" -ForegroundColor Cyan
    if ($externalDelegates -gt 0) {
        Write-Host "    [WARNING]  $externalDelegates delegations to external users" -ForegroundColor Red
    }
} catch {
    Write-Warning "Failed to check mailbox permissions: $_"
}
#endregion

#region Retention Policies
Write-Host "[4/6] Checking retention policies..." -ForegroundColor Yellow

try {
    # Get all retention policies
    $retentionPolicies = Get-RetentionPolicy
    
    $retentionReport = $retentionPolicies | Select-Object @{
        Name = "PolicyName"
        Expression = { $_.Name }
    }, @{
        Name = "Enabled"
        Expression = { -not $_.IsDisabled }
    }, @{
        Name = "RetentionPolicyTagLinks"
        Expression = { ($_.RetentionPolicyTagLinks | Measure-Object).Count }
    }
    
    $retentionReport | Export-Csv -Path (Join-Path $OutputFolder "RetentionPolicies.csv") -NoTypeInformation
    
    # Check mailboxes without retention policies
    $mailboxesNoRetention = $mailboxes | Where-Object { 
        $null -eq $_.RetentionPolicy -or $_.RetentionPolicy -eq ""
    } | Select-Object DisplayName, UserPrincipalName, RecipientTypeDetails, @{
        Name = "Issue"
        Expression = { "No retention policy" }
    }
    
    $mailboxesNoRetention | Export-Csv -Path (Join-Path $OutputFolder "MailboxesWithoutRetention.csv") -NoTypeInformation
    
    Write-Host "  [OK] Found $($retentionPolicies.Count) retention policies" -ForegroundColor Green
    Write-Host "    - Mailboxes without retention: $($mailboxesNoRetention.Count)" -ForegroundColor $(if($mailboxesNoRetention.Count -gt 0){'Yellow'}else{'Green'})
} catch {
    Write-Warning "Failed to check retention policies: $_"
}
#endregion

#region Litigation Hold & Audit
Write-Host "[5/6] Checking litigation hold and audit status..." -ForegroundColor Yellow

try {
    $complianceStatus = $mailboxes | Select-Object @{
        Name = "DisplayName"
        Expression = { $_.DisplayName }
    }, @{
        Name = "UserPrincipalName"
        Expression = { $_.UserPrincipalName }
    }, @{
        Name = "RecipientType"
        Expression = { $_.RecipientTypeDetails }
    }, @{
        Name = "LitigationHold"
        Expression = { $_.LitigationHoldEnabled }
    }, @{
        Name = "RetentionPolicy"
        Expression = { $_.RetentionPolicy }
    }, @{
        Name = "AuditEnabled"
        Expression = { $_.AuditEnabled }
    }, @{
        Name = "InPlaceHolds"
        Expression = { ($_.InPlaceHolds -join '; ') }
    }
    
    $complianceStatus | Export-Csv -Path (Join-Path $OutputFolder "MailboxComplianceStatus.csv") -NoTypeInformation
    
    $auditDisabled = ($complianceStatus | Where-Object { -not $_.AuditEnabled }).Count
    $onHold = ($complianceStatus | Where-Object { $_.LitigationHold -eq $true -or $_.InPlaceHolds -ne "" }).Count
    
    Write-Host "  [OK] Compliance status checked for $($mailboxes.Count) mailboxes" -ForegroundColor Green
    Write-Host "    - Mailboxes on litigation hold: $onHold" -ForegroundColor Cyan
    Write-Host "    - Mailboxes with audit disabled: $auditDisabled" -ForegroundColor $(if($auditDisabled -gt 0){'Yellow'}else{'Green'})
} catch {
    Write-Warning "Failed to check compliance status: $_"
}
#endregion

#region Summary Report
Write-Host "[6/6] Generating email hygiene summary..." -ForegroundColor Yellow

$externalFwd = ($forwardingMailboxes | Where-Object { $_.ForwardingAddress -notlike "*@*onmicrosoft.com" }).Count
$personalEmailFwd = ($forwardingMailboxes | Where-Object { $_.Issue -eq "Forwarding to personal email" }).Count

$summary = @"
Email Hygiene & Compliance Audit Report
Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")

AUTO-FORWARDING:
- Mailboxes with auto-forwarding: $($forwardingMailboxes.Count)
- Forwarding to external addresses: $externalFwd
- Forwarding to personal email: $personalEmailFwd

INBOX RULES:
- Suspicious inbox rules found: $($suspiciousRules.Count)
- Rules with forwarding/redirect: $(($suspiciousRules | Where-Object { $_.Issue -eq "Forwarding/Redirect rule" }).Count)
- Rules with auto-delete: $(($suspiciousRules | Where-Object { $_.Issue -eq "Auto-delete rule" }).Count)

MAILBOX PERMISSIONS:
- Total delegate permissions: $($delegatePermissions.Count)
- External user delegations: $externalDelegates

RETENTION & COMPLIANCE:
- Retention policies configured: $($retentionPolicies.Count)
- Mailboxes without retention: $($mailboxesNoRetention.Count)
- Mailboxes on litigation hold: $onHold
- Mailboxes with audit disabled: $auditDisabled

CRITICAL FINDINGS:
$(if($externalFwd -gt 0){"[CRITICAL] $externalFwd mailboxes forwarding to external addresses - SECURITY RISK"}else{""})
$(if($personalEmailFwd -gt 0){"[WARNING]  $personalEmailFwd mailboxes forwarding to personal email accounts"}else{""})
$(if($externalDelegates -gt 0){"[WARNING]  $externalDelegates external users have mailbox access"}else{""})
$(if($auditDisabled -gt ($mailboxes.Count * 0.1)){"[WARNING]  More than 10% of mailboxes have auditing disabled"}else{""})
$(if($mailboxesNoRetention.Count -gt 0){"[WARNING]  $($mailboxesNoRetention.Count) mailboxes lack retention policies"}else{""})

RECOMMENDATIONS:
1. CRITICAL: Review and disable external auto-forwarding (especially to personal email)
2. HIGH: Enable mailbox auditing for all mailboxes
3. HIGH: Implement organization-wide retention policies
4. MEDIUM: Review and cleanup suspicious inbox rules
5. MEDIUM: Review external user mailbox delegations
6. MEDIUM: Block auto-forwarding to external domains via transport rules
7. LOW: Regular review of mailbox permissions (quarterly)
8. LOW: Consider Data Loss Prevention (DLP) policies for sensitive data

"@

$summary | Out-File -FilePath (Join-Path $OutputFolder "EmailHygiene-Summary.txt") -Encoding UTF8
Write-Host "  [OK] Email hygiene summary generated" -ForegroundColor Green

Write-Host "`n" + ("="*60) -ForegroundColor Cyan
if ($externalFwd -gt 0 -or $personalEmailFwd -gt 0) {
    Write-Host "[CRITICAL] CRITICAL EMAIL SECURITY ISSUES FOUND!" -ForegroundColor Red
} else {
    Write-Host "Email Hygiene Export Complete!" -ForegroundColor Green
}
Write-Host ("="*60) -ForegroundColor Cyan
Write-Host "`nResults saved to: $OutputFolder" -ForegroundColor Cyan
Write-Host ""
#endregion

