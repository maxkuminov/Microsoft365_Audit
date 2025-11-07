<#
.SYNOPSIS
    Export Microsoft 365 users, licensing, and authentication details.

.DESCRIPTION
    Collects comprehensive user data including:
    - User accounts (display name, UPN, email, status)
    - License assignments and SKUs
    - MFA status and authentication methods
    - Admin role assignments
    - Sign-in activity
    - Guest vs member accounts

.PARAMETER OutputPath
    Path to save the exported data. Defaults to ../Data/[timestamp]/

.EXAMPLE
    .\01-Export-Users.ps1
    Export user data to default timestamped folder.

.EXAMPLE
    .\01-Export-Users.ps1 -OutputPath "C:\Audit\Users"
    Export user data to specific folder.

.NOTES
    Author: IT Audit
    Date: 2025-11-05
    Requires: Microsoft.Graph module and active connection
    Run 00-Connect-M365.ps1 first to establish connections
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$OutputPath
)

$ErrorActionPreference = "Stop"

# Banner
Write-Host "=============================================================" -ForegroundColor Cyan
Write-Host "     Microsoft 365 User & License Audit                    " -ForegroundColor Cyan
Write-Host "=============================================================" -ForegroundColor Cyan

# Setup output path
if ([string]::IsNullOrEmpty($OutputPath)) {
    $timestamp = Get-Date -Format "yyyy-MM-dd"
    $scriptRoot = Split-Path -Parent $PSCommandPath
    $OutputPath = Join-Path (Split-Path -Parent $scriptRoot) "Data\$timestamp"
}

# Create output directory
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    Write-Host "Created output directory: $OutputPath" -ForegroundColor Green
}

# Verify Graph connection
try {
    $context = Get-MgContext
    if ($null -eq $context) {
        throw "Not connected to Microsoft Graph. Run 00-Connect-M365.ps1 first."
    }
    Write-Host "[OK] Connected to tenant: $($context.TenantId)`n" -ForegroundColor Green
} catch {
    Write-Error "Microsoft Graph connection required. Run 00-Connect-M365.ps1 first."
    exit 1
}

# Function to get MFA status
function Get-UserMfaStatus {
    param($UserId)
    
    try {
        $methods = Get-MgUserAuthenticationMethod -UserId $UserId -ErrorAction SilentlyContinue
        
        if ($null -eq $methods -or $methods.Count -eq 0) {
            return "Disabled"
        }
        
        $hasStrongAuth = $false
        foreach ($method in $methods) {
            $methodType = $method.AdditionalProperties.'@odata.type'
            if ($methodType -in @(
                '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod',
                '#microsoft.graph.phoneAuthenticationMethod',
                '#microsoft.graph.fido2AuthenticationMethod',
                '#microsoft.graph.windowsHelloForBusinessAuthenticationMethod'
            )) {
                $hasStrongAuth = $true
                break
            }
        }
        
        return $(if ($hasStrongAuth) { "Enabled" } else { "Disabled" })
    } catch {
        return "Unknown"
    }
}

Write-Host "[1/5] Retrieving user accounts..." -ForegroundColor Yellow

# Get all users with key properties (excluding SignInActivity which requires AuditLog.Read.All)
$users = Get-MgUser -All -Property @(
    'Id',
    'DisplayName',
    'UserPrincipalName',
    'Mail',
    'UserType',
    'AccountEnabled',
    'CreatedDateTime',
    'AssignedLicenses',
    'Department',
    'JobTitle',
    'CompanyName',
    'OfficeLocation'
)

Write-Host "  [OK] Found $($users.Count) users" -ForegroundColor Green

# Check if we have AuditLog.Read.All permission for SignInActivity
Write-Host "  [INFO] Checking for sign-in activity permissions..." -ForegroundColor Gray
$hasSignInPermission = $false
try {
    $testUser = $users | Select-Object -First 1
    if ($testUser) {
        $testSignIn = Get-MgUser -UserId $testUser.Id -Property SignInActivity -ErrorAction Stop
        $hasSignInPermission = $true
        Write-Host "  [OK] Sign-in activity data available" -ForegroundColor Green
    }
} catch {
    Write-Host "  [WARNING] Sign-in activity data not available (requires AuditLog.Read.All permission)" -ForegroundColor Yellow
}

Write-Host "`n[2/5] Retrieving license details..." -ForegroundColor Yellow

# Get available SKUs (license types)
$skus = Get-MgSubscribedSku
$skuHashtable = @{}
foreach ($sku in $skus) {
    $skuHashtable[$sku.SkuId] = $sku.SkuPartNumber
}

Write-Host "  [OK] Found $($skus.Count) license types" -ForegroundColor Green

Write-Host "`n[3/5] Processing user details (this may take a while)..." -ForegroundColor Yellow

$userDetails = @()
$counter = 0
$total = $users.Count

foreach ($user in $users) {
    $counter++
    $percentComplete = [math]::Round(($counter / $total) * 100)
    Write-Progress -Activity "Processing Users" -Status "User $counter of $total ($percentComplete%)" -PercentComplete $percentComplete
    
    # Get license info
    $licenses = @()
    if ($user.AssignedLicenses.Count -gt 0) {
        foreach ($license in $user.AssignedLicenses) {
            $skuName = $skuHashtable[$license.SkuId]
            if ($skuName) {
                $licenses += $skuName
            }
        }
    }
    $licensesString = ($licenses -join "; ")
    
    # Get MFA status (sample every 10th user for speed, or all if fewer than 50 users)
    $mfaStatus = "Not Checked"
    if ($total -lt 50 -or $counter % 10 -eq 0) {
        $mfaStatus = Get-UserMfaStatus -UserId $user.Id
    }
    
    # Get last sign-in (only if we have permission)
    $lastSignIn = $null
    $lastInteractiveSignIn = $null
    if ($hasSignInPermission) {
        try {
            $signInData = Get-MgUser -UserId $user.Id -Property SignInActivity -ErrorAction Stop
            if ($signInData.SignInActivity) {
                $lastSignIn = $signInData.SignInActivity.LastSignInDateTime
                $lastInteractiveSignIn = $signInData.SignInActivity.LastNonInteractiveSignInDateTime
            }
        } catch {
            # Silently skip if permission denied
        }
    }
    
    # Create user object
    $userObj = [PSCustomObject]@{
        'Display Name' = $user.DisplayName
        'User Principal Name' = $user.UserPrincipalName
        'Email' = $user.Mail
        'User Type' = $user.UserType
        'Account Enabled' = $user.AccountEnabled
        'Job Title' = $user.JobTitle
        'Department' = $user.Department
        'Office Location' = $user.OfficeLocation
        'Company' = $user.CompanyName
        'Created Date' = $user.CreatedDateTime
        'Last Sign-In' = $lastSignIn
        'Last Interactive Sign-In' = $lastInteractiveSignIn
        'Licenses Assigned' = $licensesString
        'License Count' = $licenses.Count
        'MFA Status' = $mfaStatus
        'User ID' = $user.Id
    }
    
    $userDetails += $userObj
}

Write-Progress -Activity "Processing Users" -Completed

Write-Host "  [OK] Processed $counter users" -ForegroundColor Green

Write-Host "`n[4/5] Retrieving admin role assignments..." -ForegroundColor Yellow

# Get directory role assignments
$adminUsers = @()
$directoryRoles = Get-MgDirectoryRole -All

foreach ($role in $directoryRoles) {
    $roleMembers = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id
    
    foreach ($member in $roleMembers) {
        $adminUsers += [PSCustomObject]@{
            'User Principal Name' = $member.AdditionalProperties.userPrincipalName
            'Display Name' = $member.AdditionalProperties.displayName
            'Role Name' = $role.DisplayName
            'Role ID' = $role.Id
        }
    }
}

Write-Host "  [OK] Found $($adminUsers.Count) admin role assignments" -ForegroundColor Green

Write-Host "`n[5/5] Generating license summary..." -ForegroundColor Yellow

# License summary
$licenseSummary = @()
foreach ($sku in $skus) {
    $licenseSummary += [PSCustomObject]@{
        'License Name' = $sku.SkuPartNumber
        'SKU ID' = $sku.SkuId
        'Total Units' = $sku.PrepaidUnits.Enabled
        'Consumed Units' = $sku.ConsumedUnits
        'Available Units' = $sku.PrepaidUnits.Enabled - $sku.ConsumedUnits
        'Warning Units' = $sku.PrepaidUnits.Warning
        'Suspended Units' = $sku.PrepaidUnits.Suspended
    }
}

Write-Host "  [OK] License summary generated" -ForegroundColor Green

# Export data
Write-Host "`n" + ("="*60) -ForegroundColor Cyan
Write-Host "Exporting data..." -ForegroundColor Cyan
Write-Host ("="*60) -ForegroundColor Cyan

$usersFile = Join-Path $OutputPath "Users.csv"
$adminFile = Join-Path $OutputPath "AdminRoles.csv"
$licenseFile = Join-Path $OutputPath "Licenses.csv"

$userDetails | Export-Csv -Path $usersFile -NoTypeInformation -Encoding UTF8
Write-Host "[OK] Users exported to: $usersFile" -ForegroundColor Green

$adminUsers | Export-Csv -Path $adminFile -NoTypeInformation -Encoding UTF8
Write-Host "[OK] Admin roles exported to: $adminFile" -ForegroundColor Green

$licenseSummary | Export-Csv -Path $licenseFile -NoTypeInformation -Encoding UTF8
Write-Host "[OK] Licenses exported to: $licenseFile" -ForegroundColor Green

# Generate summary report
$summary = @"
Microsoft 365 User Audit Summary
Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Tenant ID: $($context.TenantId)

USER STATISTICS
===============
Total Users:              $($users.Count)
Enabled Accounts:         $(($userDetails | Where-Object {$_.'Account Enabled' -eq $true}).Count)
Disabled Accounts:        $(($userDetails | Where-Object {$_.'Account Enabled' -eq $false}).Count)
Guest Users:              $(($userDetails | Where-Object {$_.'User Type' -eq 'Guest'}).Count)
Member Users:             $(($userDetails | Where-Object {$_.'User Type' -eq 'Member'}).Count)
Licensed Users:           $(($userDetails | Where-Object {$_.'License Count' -gt 0}).Count)
Unlicensed Users:         $(($userDetails | Where-Object {$_.'License Count' -eq 0}).Count)

ADMIN ROLES
===========
Admin Role Assignments:   $($adminUsers.Count)
Unique Admin Users:       $(($adminUsers | Select-Object -Unique 'User Principal Name').Count)

LICENSE SUMMARY
===============
Total License Types:      $($licenseSummary.Count)
Total License Units:      $(($licenseSummary | Measure-Object -Property 'Total Units' -Sum).Sum)
Consumed License Units:   $(($licenseSummary | Measure-Object -Property 'Consumed Units' -Sum).Sum)
Available License Units:  $(($licenseSummary | Measure-Object -Property 'Available Units' -Sum).Sum)

Top 5 Most Used Licenses:
$($licenseSummary | Sort-Object 'Consumed Units' -Descending | Select-Object -First 5 | ForEach-Object { "  - $($_.'License Name'): $($_.'Consumed Units') / $($_.'Total Units')" } | Out-String)

FINDINGS & RECOMMENDATIONS
==========================
$(if (($userDetails | Where-Object {$_.'License Count' -eq 0 -and $_.'Account Enabled' -eq $true -and $_.'User Type' -eq 'Member'}).Count -gt 0) {
    "[WARNING] Warning: $(($userDetails | Where-Object {$_.'License Count' -eq 0 -and $_.'Account Enabled' -eq $true -and $_.'User Type' -eq 'Member'}).Count) enabled member users without licenses"
} else {
    "[OK] No enabled users without licenses"
})

$(if (($userDetails | Where-Object {$_.'Account Enabled' -eq $false -and $_.'License Count' -gt 0}).Count -gt 0) {
    "[WARNING] Warning: $(($userDetails | Where-Object {$_.'Account Enabled' -eq $false -and $_.'License Count' -gt 0}).Count) disabled users still have licenses assigned"
} else {
    "[OK] No licenses assigned to disabled accounts"
})

$(if (($licenseSummary | Where-Object {$_.'Available Units' -lt 5 -and $_.'Available Units' -ge 0}).Count -gt 0) {
    "[WARNING] Warning: $(($licenseSummary | Where-Object {$_.'Available Units' -lt 5}).Count) license type(s) running low (< 5 available)"
})

FILES GENERATED
===============
- $usersFile
- $adminFile
- $licenseFile
- $($OutputPath)\UserInventory-Summary.txt (this file)

"@

$summaryFile = Join-Path $OutputPath "UserInventory-Summary.txt"
$summary | Out-File -FilePath $summaryFile -Encoding UTF8
Write-Host "[OK] Summary report: $summaryFile" -ForegroundColor Green

# Display summary to console
Write-Host "`n" + ("="*60) -ForegroundColor Cyan
Write-Host $summary -ForegroundColor White
Write-Host ("="*60) -ForegroundColor Cyan

Write-Host "`n[OK] User audit complete!" -ForegroundColor Green
Write-Host "All data exported to: $OutputPath" -ForegroundColor Cyan

