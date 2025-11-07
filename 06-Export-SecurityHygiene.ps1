<#
.SYNOPSIS
    Export security hygiene issues from M365 environment.

.DESCRIPTION
    This script identifies authentication weaknesses, legacy protocols,
    MFA gaps, and privileged access concerns in Microsoft 365. Critical
    for environments that grew without formal security policies.

.PARAMETER OutputFolder
    Folder path for exported data. Defaults to ..\Data\[timestamp]

.EXAMPLE
    .\06-Export-SecurityHygiene.ps1
    Export security hygiene data with default settings.

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
Write-Host "     Security Hygiene Issues Export                        " -ForegroundColor Cyan
Write-Host "     IT Audit Toolkit                                      " -ForegroundColor Cyan
Write-Host "=============================================================" -ForegroundColor Cyan

Write-Host "`nOutput folder: $OutputFolder" -ForegroundColor Yellow
Write-Host ""

#region Legacy Authentication Protocols
Write-Host "[1/6] Checking legacy authentication protocols..." -ForegroundColor Yellow

try {
    # Check for POP3/IMAP enabled mailboxes
    $casMailboxes = Get-CASMailbox -ResultSize Unlimited
    
    $legacyProtocolUsers = $casMailboxes | Where-Object {
        $_.PopEnabled -eq $true -or 
        $_.ImapEnabled -eq $true -or
        $_.SmtpClientAuthenticationDisabled -eq $false
    } | Select-Object @{
        Name = "DisplayName"
        Expression = { (Get-Mailbox -Identity $_.Identity).DisplayName }
    }, @{
        Name = "UserPrincipalName"
        Expression = { $_.PrimarySmtpAddress }
    }, @{
        Name = "POPEnabled"
        Expression = { $_.PopEnabled }
    }, @{
        Name = "IMAPEnabled"
        Expression = { $_.ImapEnabled }
    }, @{
        Name = "SMTPAuthEnabled"
        Expression = { -not $_.SmtpClientAuthenticationDisabled }
    }, @{
        Name = "SecurityRisk"
        Expression = { "Legacy authentication enabled" }
    }
    
    $legacyProtocolUsers | Export-Csv -Path (Join-Path $OutputFolder "LegacyAuthProtocols.csv") -NoTypeInformation
    Write-Host "  [OK] Found $($legacyProtocolUsers.Count) mailboxes with legacy protocols enabled" -ForegroundColor $(if($legacyProtocolUsers.Count -gt 0){'Yellow'}else{'Green'})
} catch {
    Write-Warning "Failed to check legacy protocols: $_"
}
#endregion

#region MFA Status
Write-Host "[2/6] Checking MFA enrollment..." -ForegroundColor Yellow

try {
    $allUsers = Get-MgUser -All -Property Id,DisplayName,UserPrincipalName,AccountEnabled
    $mfaStatus = @()
    
    $userCount = 0
    foreach ($user in $allUsers | Where-Object { $_.AccountEnabled -eq $true }) {
        $userCount++
        Write-Progress -Activity "Checking MFA status" -Status "$userCount of $($allUsers.Count)" -PercentComplete (($userCount / $allUsers.Count) * 100)
        
        try {
            $authMethods = Get-MgUserAuthenticationMethod -UserId $user.Id -ErrorAction SilentlyContinue
            
            # Count strong auth methods (excluding password)
            $strongMethods = $authMethods | Where-Object {
                $_.AdditionalProperties['@odata.type'] -ne '#microsoft.graph.passwordAuthenticationMethod'
            }
            
            $mfaStatus += [PSCustomObject]@{
                DisplayName = $user.DisplayName
                UserPrincipalName = $user.UserPrincipalName
                MFAEnabled = $strongMethods.Count -gt 0
                AuthMethodCount = $strongMethods.Count
                AuthMethods = ($authMethods.AdditionalProperties['@odata.type'] | ForEach-Object { $_ -replace '#microsoft.graph.', '' -replace 'AuthenticationMethod', '' }) -join ', '
                Issue = if ($strongMethods.Count -eq 0) { "No MFA configured" } else { "" }
            }
        } catch {
            $mfaStatus += [PSCustomObject]@{
                DisplayName = $user.DisplayName
                UserPrincipalName = $user.UserPrincipalName
                MFAEnabled = $false
                AuthMethodCount = 0
                AuthMethods = "Unable to retrieve"
                Issue = "Error checking MFA status"
            }
        }
    }
    
    $mfaStatus | Export-Csv -Path (Join-Path $OutputFolder "MFAStatus.csv") -NoTypeInformation
    
    $noMFA = ($mfaStatus | Where-Object { -not $_.MFAEnabled }).Count
    Write-Host "  [OK] Found $noMFA users without MFA configured" -ForegroundColor $(if($noMFA -gt 0){'Red'}else{'Green'})
} catch {
    Write-Warning "Failed to check MFA status: $_"
}
#endregion

#region Privileged Accounts
Write-Host "[3/6] Auditing privileged accounts..." -ForegroundColor Yellow

try {
    $adminRoles = Get-MgDirectoryRole -All
    $privilegedUsers = @()
    
    foreach ($role in $adminRoles) {
        $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All
        
        foreach ($member in $members) {
            try {
                $user = Get-MgUser -UserId $member.Id -Property DisplayName,UserPrincipalName,AccountEnabled -ErrorAction SilentlyContinue
                
                if ($null -ne $user) {
                    # Check MFA status for this admin
                    $authMethods = Get-MgUserAuthenticationMethod -UserId $user.Id -ErrorAction SilentlyContinue
                    $strongMethods = $authMethods | Where-Object {
                        $_.AdditionalProperties['@odata.type'] -ne '#microsoft.graph.passwordAuthenticationMethod'
                    }
                    
                    $privilegedUsers += [PSCustomObject]@{
                        DisplayName = $user.DisplayName
                        UserPrincipalName = $user.UserPrincipalName
                        Role = $role.DisplayName
                        AccountEnabled = $user.AccountEnabled
                        MFAEnabled = $strongMethods.Count -gt 0
                        Issue = if ($strongMethods.Count -eq 0) { "Admin without MFA" } else { "" }
                    }
                }
            } catch {
                # Silent continue for service principals
            }
        }
    }
    
    # Export all privileged users
    $privilegedUsers | Export-Csv -Path (Join-Path $OutputFolder "PrivilegedAccounts.csv") -NoTypeInformation
    
    # Count Global Admins
    $globalAdmins = $privilegedUsers | Where-Object { $_.Role -eq "Global Administrator" }
    $adminsWithoutMFA = $privilegedUsers | Where-Object { -not $_.MFAEnabled }
    
    Write-Host "  [OK] Found $($privilegedUsers.Count) privileged accounts" -ForegroundColor Cyan
    Write-Host "    - Global Admins: $($globalAdmins.Count) $(if($globalAdmins.Count -gt 5){'([WARNING] Should be <5)'}else{''})" -ForegroundColor $(if($globalAdmins.Count -gt 5){'Yellow'}else{'Green'})
    Write-Host "    - Admins without MFA: $($adminsWithoutMFA.Count) $(if($adminsWithoutMFA.Count -gt 0){'([CRITICAL] CRITICAL)'}else{''})" -ForegroundColor $(if($adminsWithoutMFA.Count -gt 0){'Red'}else{'Green'})
} catch {
    Write-Warning "Failed to audit privileged accounts: $_"
}
#endregion

#region Conditional Access Policies
Write-Host "[4/6] Checking Conditional Access policies..." -ForegroundColor Yellow

try {
    $caPolicies = Get-MgIdentityConditionalAccessPolicy -All
    
    $caReport = $caPolicies | Select-Object @{
        Name = "PolicyName"
        Expression = { $_.DisplayName }
    }, @{
        Name = "State"
        Expression = { $_.State }
    }, @{
        Name = "CreatedDate"
        Expression = { $_.CreatedDateTime }
    }, @{
        Name = "ModifiedDate"
        Expression = { $_.ModifiedDateTime }
    }, @{
        Name = "GrantControls"
        Expression = { ($_.GrantControls.BuiltInControls -join ', ') }
    }, @{
        Name = "SessionControls"
        Expression = { 
            $controls = @()
            if ($_.SessionControls.SignInFrequency) { $controls += "SignInFrequency" }
            if ($_.SessionControls.CloudAppSecurity) { $controls += "CloudAppSecurity" }
            if ($_.SessionControls.PersistentBrowser) { $controls += "PersistentBrowser" }
            $controls -join ', '
        }
    }
    
    $caReport | Export-Csv -Path (Join-Path $OutputFolder "ConditionalAccessPolicies.csv") -NoTypeInformation
    Write-Host "  [OK] Found $($caPolicies.Count) Conditional Access policies" -ForegroundColor Green
    
    $enabledPolicies = ($caPolicies | Where-Object { $_.State -eq "enabled" }).Count
    Write-Host "    - Enabled: $enabledPolicies" -ForegroundColor Green
    Write-Host "    - Disabled/Report-only: $($caPolicies.Count - $enabledPolicies)" -ForegroundColor Yellow
} catch {
    Write-Warning "Failed to check Conditional Access policies: $_"
}
#endregion

#region Password Policy
Write-Host "[5/6] Checking password policies..." -ForegroundColor Yellow

try {
    $orgSettings = Get-MgOrganization
    
    $passwordPolicy = $orgSettings | Select-Object @{
        Name = "DisplayName"
        Expression = { $_.DisplayName }
    }, @{
        Name = "PasswordExpirationDays"
        Expression = { 
            $policy = $_.PasswordValidityPeriodInDays
            if ($null -eq $policy) { "Never expires" } else { $policy }
        }
    }, @{
        Name = "PasswordNotificationDays"
        Expression = { $_.PasswordNotificationWindowInDays }
    }
    
    $passwordPolicy | Export-Csv -Path (Join-Path $OutputFolder "PasswordPolicy.csv") -NoTypeInformation
    Write-Host "  [OK] Password policy exported" -ForegroundColor Green
} catch {
    Write-Warning "Failed to check password policy: $_"
}
#endregion

#region Summary Report
Write-Host "[6/6] Generating security summary..." -ForegroundColor Yellow

$noMFACount = ($mfaStatus | Where-Object { -not $_.MFAEnabled }).Count
$legacyProtocolCount = $legacyProtocolUsers.Count
$globalAdminCount = $globalAdmins.Count
$adminsNoMFACount = $adminsWithoutMFA.Count

$summary = @"
Security Hygiene Audit Report
Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")

AUTHENTICATION ISSUES:
- Users without MFA: $noMFACount
- Mailboxes with legacy protocols (POP/IMAP/SMTP AUTH): $legacyProtocolCount

PRIVILEGED ACCESS:
- Total privileged accounts: $($privilegedUsers.Count)
- Global Administrators: $globalAdminCount $(if($globalAdminCount -gt 5){"[WARNING] (Recommendation: <5)"}else{""})
- Admins without MFA: $adminsNoMFACount $(if($adminsNoMFACount -gt 0){"[CRITICAL] CRITICAL RISK"}else{""})

CONDITIONAL ACCESS:
- Total policies: $($caPolicies.Count)
- Enabled policies: $enabledPolicies

CRITICAL FINDINGS:
$(if($adminsNoMFACount -gt 0){"[WARNING]  $adminsNoMFACount privileged accounts lack MFA - IMMEDIATE ACTION REQUIRED"}else{""})
$(if($legacyProtocolCount -gt 10){"[WARNING]  $legacyProtocolCount mailboxes using legacy authentication"}else{""})
$(if($noMFACount -gt ($mfaStatus.Count * 0.5)){"[WARNING]  More than 50% of users lack MFA"}else{""})
$(if($globalAdminCount -gt 5){"[WARNING]  Too many Global Administrators ($globalAdminCount) - reduce to <5"}else{""})

RECOMMENDATIONS:
1. IMMEDIATE: Enable MFA for all privileged accounts
2. HIGH: Enforce MFA for all users via Conditional Access
3. HIGH: Disable legacy authentication protocols (POP/IMAP/SMTP AUTH)
4. MEDIUM: Reduce Global Administrator count to <5 (use role-based access)
5. MEDIUM: Implement Conditional Access policies for:
   - Require MFA for admins
   - Block legacy authentication
   - Require compliant devices
   - Risk-based sign-in policies

"@

$summary | Out-File -FilePath (Join-Path $OutputFolder "SecurityHygiene-Summary.txt") -Encoding UTF8
Write-Host "  [OK] Security summary generated" -ForegroundColor Green

Write-Host "`n" + ("="*60) -ForegroundColor Cyan
if ($adminsNoMFACount -gt 0 -or $legacyProtocolCount -gt 10 -or $globalAdminCount -gt 10) {
    Write-Host "[WARNING]  CRITICAL SECURITY ISSUES FOUND!" -ForegroundColor Red
} else {
    Write-Host "Security Export Complete!" -ForegroundColor Green
}
Write-Host ("="*60) -ForegroundColor Cyan
Write-Host "`nResults saved to: $OutputFolder" -ForegroundColor Cyan
Write-Host ""
#endregion

