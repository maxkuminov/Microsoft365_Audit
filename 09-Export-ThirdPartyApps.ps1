<#
.SYNOPSIS
    Export third-party applications and OAuth consent data from Azure AD.

.DESCRIPTION
    This script identifies third-party apps, OAuth grants, risky permissions,
    and apps without owners. Critical for organizations that grew without
    formal application governance.

.PARAMETER OutputFolder
    Folder path for exported data. Defaults to ..\Data\[timestamp]

.EXAMPLE
    .\09-Export-ThirdPartyApps.ps1
    Export third-party app data with default settings.

.NOTES
    Author: IT Audit
    Date: 2025-11-05
    
    Prerequisites:
    - Run 00-Connect-M365.ps1 first to establish connections
    - Requires Microsoft.Graph module
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
Write-Host "     Third-Party Apps & OAuth Consents Export              " -ForegroundColor Cyan
Write-Host "     IT Audit Toolkit                                      " -ForegroundColor Cyan
Write-Host "=============================================================" -ForegroundColor Cyan

Write-Host "`nOutput folder: $OutputFolder" -ForegroundColor Yellow
Write-Host ""

#region OAuth Consent Grants
Write-Host "[1/5] Exporting OAuth consent grants..." -ForegroundColor Yellow

try {
    $oauthGrants = Get-MgOauth2PermissionGrant -All
    
    $oauthReport = @()
    foreach ($grant in $oauthGrants) {
        try {
            $servicePrincipal = Get-MgServicePrincipal -ServicePrincipalId $grant.ClientId -ErrorAction SilentlyContinue
            
            $oauthReport += [PSCustomObject]@{
                ClientDisplayName = if ($servicePrincipal) { $servicePrincipal.DisplayName } else { "Unknown" }
                ClientId = $grant.ClientId
                ConsentType = $grant.ConsentType
                PrincipalId = $grant.PrincipalId
                Scope = $grant.Scope
                StartTime = $grant.StartTime
                Issue = if ($grant.ConsentType -eq "AllPrincipals") { "Organization-wide consent" } else { "" }
                RiskLevel = if ($grant.Scope -like "*Mail.ReadWrite*" -or $grant.Scope -like "*Files.ReadWrite.All*" -or $grant.Scope -like "*Directory.ReadWrite.All*") { "High" } else { "Medium" }
            }
        } catch {
            # Silent continue
        }
    }
    
    $oauthReport | Export-Csv -Path (Join-Path $OutputFolder "OAuthConsentGrants.csv") -NoTypeInformation
    
    $orgWideConsents = ($oauthReport | Where-Object { $_.ConsentType -eq "AllPrincipals" }).Count
    $highRiskGrants = ($oauthReport | Where-Object { $_.RiskLevel -eq "High" }).Count
    
    Write-Host "  [OK] Found $($oauthGrants.Count) OAuth consent grants" -ForegroundColor Cyan
    Write-Host "    - Organization-wide consents: $orgWideConsents" -ForegroundColor $(if($orgWideConsents -gt 10){'Yellow'}else{'Green'})
    Write-Host "    - High-risk permissions: $highRiskGrants" -ForegroundColor $(if($highRiskGrants -gt 0){'Red'}else{'Green'})
} catch {
    Write-Warning "Failed to export OAuth consents: $_"
}
#endregion

#region Service Principals
Write-Host "[2/5] Exporting service principals..." -ForegroundColor Yellow

try {
    $servicePrincipals = Get-MgServicePrincipal -All -Property Id,DisplayName,AppId,CreatedDateTime,ServicePrincipalType,AccountEnabled
    
    $spReport = @()
    $spCount = 0
    
    foreach ($sp in $servicePrincipals) {
        $spCount++
        Write-Progress -Activity "Checking service principals" -Status "$spCount of $($servicePrincipals.Count)" -PercentComplete (($spCount / $servicePrincipals.Count) * 100)
        
        try {
            # Get owners
            $owners = Get-MgServicePrincipalOwner -ServicePrincipalId $sp.Id -ErrorAction SilentlyContinue
            
            $spReport += [PSCustomObject]@{
                DisplayName = $sp.DisplayName
                AppId = $sp.AppId
                ServicePrincipalId = $sp.Id
                Type = $sp.ServicePrincipalType
                CreatedDate = $sp.CreatedDateTime
                Enabled = $sp.AccountEnabled
                OwnerCount = $owners.Count
                Issue = if ($owners.Count -eq 0) { "No owners" } else { "" }
            }
        } catch {
            # Silent continue
        }
    }
    
    $spReport | Export-Csv -Path (Join-Path $OutputFolder "ServicePrincipals.csv") -NoTypeInformation
    
    $noOwners = ($spReport | Where-Object { $_.OwnerCount -eq 0 }).Count
    Write-Host "  [OK] Found $($servicePrincipals.Count) service principals" -ForegroundColor Cyan
    Write-Host "    - Service principals without owners: $noOwners" -ForegroundColor $(if($noOwners -gt 0){'Yellow'}else{'Green'})
} catch {
    Write-Warning "Failed to export service principals: $_"
}
#endregion

#region Application Registrations
Write-Host "[3/5] Exporting application registrations..." -ForegroundColor Yellow

try {
    $applications = Get-MgApplication -All -Property Id,DisplayName,AppId,CreatedDateTime,SignInAudience
    
    $appReport = @()
    $appCount = 0
    
    foreach ($app in $applications) {
        $appCount++
        Write-Progress -Activity "Checking applications" -Status "$appCount of $($applications.Count)" -PercentComplete (($appCount / $applications.Count) * 100)
        
        try {
            # Get owners
            $owners = Get-MgApplicationOwner -ApplicationId $app.Id -ErrorAction SilentlyContinue
            
            # Get credentials (certificates and secrets)
            $appDetails = Get-MgApplication -ApplicationId $app.Id -Property PasswordCredentials,KeyCredentials -ErrorAction SilentlyContinue
            
            # Check for expiring or expired credentials
            $expiredCreds = 0
            $expiringSoonCreds = 0
            $today = Get-Date
            
            foreach ($cred in $appDetails.PasswordCredentials) {
                if ($cred.EndDateTime -lt $today) {
                    $expiredCreds++
                } elseif ($cred.EndDateTime -lt $today.AddDays(30)) {
                    $expiringSoonCreds++
                }
            }
            
            foreach ($cred in $appDetails.KeyCredentials) {
                if ($cred.EndDateTime -lt $today) {
                    $expiredCreds++
                } elseif ($cred.EndDateTime -lt $today.AddDays(30)) {
                    $expiringSoonCreds++
                }
            }
            
            $appReport += [PSCustomObject]@{
                DisplayName = $app.DisplayName
                AppId = $app.AppId
                ApplicationId = $app.Id
                CreatedDate = $app.CreatedDateTime
                SignInAudience = $app.SignInAudience
                OwnerCount = $owners.Count
                PasswordCredentialsCount = $appDetails.PasswordCredentials.Count
                CertificateCredentialsCount = $appDetails.KeyCredentials.Count
                ExpiredCredentials = $expiredCreds
                ExpiringSoon = $expiringSoonCreds
                Issue = if ($owners.Count -eq 0) { "No owners" } elseif ($expiredCreds -gt 0) { "Expired credentials" } elseif ($expiringSoonCreds -gt 0) { "Credentials expiring soon" } else { "" }
            }
        } catch {
            # Silent continue
        }
    }
    
    $appReport | Export-Csv -Path (Join-Path $OutputFolder "ApplicationRegistrations.csv") -NoTypeInformation
    
    $noOwners = ($appReport | Where-Object { $_.OwnerCount -eq 0 }).Count
    $expiredCreds = ($appReport | Where-Object { $_.ExpiredCredentials -gt 0 }).Count
    $expiringSoon = ($appReport | Where-Object { $_.ExpiringSoon -gt 0 }).Count
    
    Write-Host "  [OK] Found $($applications.Count) application registrations" -ForegroundColor Cyan
    Write-Host "    - Apps without owners: $noOwners" -ForegroundColor $(if($noOwners -gt 0){'Yellow'}else{'Green'})
    Write-Host "    - Apps with expired credentials: $expiredCreds" -ForegroundColor $(if($expiredCreds -gt 0){'Red'}else{'Green'})
    Write-Host "    - Apps with credentials expiring soon: $expiringSoon" -ForegroundColor $(if($expiringSoon -gt 0){'Yellow'}else{'Green'})
} catch {
    Write-Warning "Failed to export application registrations: $_"
}
#endregion

#region High-Risk Permissions
Write-Host "[4/5] Identifying high-risk permission grants..." -ForegroundColor Yellow

try {
    # Define high-risk permissions
    $highRiskPerms = @(
        "Mail.ReadWrite",
        "Mail.ReadWrite.All",
        "Mail.Send",
        "Files.ReadWrite.All",
        "Directory.ReadWrite.All",
        "User.ReadWrite.All",
        "Group.ReadWrite.All",
        "RoleManagement.ReadWrite.Directory",
        "Application.ReadWrite.All"
    )
    
    $highRiskGrants = $oauthReport | Where-Object {
        $scope = $_.Scope
        $hasHighRiskPerm = $false
        foreach ($perm in $highRiskPerms) {
            if ($scope -like "*$perm*") {
                $hasHighRiskPerm = $true
                break
            }
        }
        $hasHighRiskPerm
    } | Select-Object ClientDisplayName, ConsentType, Scope, @{
        Name = "HighRiskPermissions"
        Expression = {
            $scope = $_.Scope
            $found = @()
            foreach ($perm in $highRiskPerms) {
                if ($scope -like "*$perm*") {
                    $found += $perm
                }
            }
            $found -join ', '
        }
    }
    
    $highRiskGrants | Export-Csv -Path (Join-Path $OutputFolder "HighRiskPermissionGrants.csv") -NoTypeInformation
    Write-Host "  [OK] Found $($highRiskGrants.Count) apps with high-risk permissions" -ForegroundColor $(if($highRiskGrants.Count -gt 0){'Red'}else{'Green'})
} catch {
    Write-Warning "Failed to identify high-risk permissions: $_"
}
#endregion

#region Summary Report
Write-Host "[5/5] Generating third-party apps summary..." -ForegroundColor Yellow

$summary = @"
Third-Party Apps & OAuth Consents Audit Report
Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")

OAUTH CONSENT GRANTS:
- Total OAuth grants: $($oauthGrants.Count)
- Organization-wide consents: $orgWideConsents
- High-risk permission grants: $($highRiskGrants.Count)

SERVICE PRINCIPALS:
- Total service principals: $($servicePrincipals.Count)
- Service principals without owners: $noOwners

APPLICATION REGISTRATIONS:
- Total applications: $($applications.Count)
- Apps without owners: $(($appReport | Where-Object { $_.OwnerCount -eq 0 }).Count)
- Apps with expired credentials: $expiredCreds
- Apps with credentials expiring soon (<30 days): $expiringSoon

HIGH-RISK PERMISSIONS GRANTED:
$(foreach ($grant in ($highRiskGrants | Select-Object -First 10)) {
"  - $($grant.ClientDisplayName): $($grant.HighRiskPermissions)"
})
$(if ($highRiskGrants.Count -gt 10) {"  ... and $($highRiskGrants.Count - 10) more"} else {""})

CRITICAL FINDINGS:
$(if($highRiskGrants.Count -gt 0){"[WARNING]  $($highRiskGrants.Count) apps have high-risk permissions (Mail.ReadWrite, Files.ReadWrite.All, etc.)"}else{""})
$(if($orgWideConsents -gt 20){"[WARNING]  Large number of organization-wide consents ($orgWideConsents)"}else{""})
$(if($expiredCreds -gt 0){"[WARNING]  $expiredCreds apps have expired credentials"}else{""})
$(if($noOwners -gt 10){"[WARNING]  $noOwners service principals lack owners"}else{""})

RECOMMENDATIONS:
1. HIGH: Review all apps with high-risk permissions
2. HIGH: Assign owners to all service principals and apps
3. HIGH: Rotate/remove expired credentials
4. MEDIUM: Review organization-wide OAuth consents
5. MEDIUM: Implement app governance policies
6. MEDIUM: Regular app permission reviews (quarterly)
7. LOW: Monitor for new app registrations
8. LOW: Consider Microsoft Defender for Cloud Apps for app risk assessment

HIGH-RISK PERMISSIONS TO REVIEW:
- Mail.ReadWrite / Mail.ReadWrite.All - Full mailbox access
- Files.ReadWrite.All - Access to all files
- Directory.ReadWrite.All - Modify directory data
- User.ReadWrite.All - Modify all users
- RoleManagement.ReadWrite.Directory - Assign admin roles

"@

$summary | Out-File -FilePath (Join-Path $OutputFolder "ThirdPartyApps-Summary.txt") -Encoding UTF8
Write-Host "  [OK] Third-party apps summary generated" -ForegroundColor Green

Write-Host "`n" + ("="*60) -ForegroundColor Cyan
if ($highRiskGrants.Count -gt 0 -or $expiredCreds -gt 0) {
    Write-Host "[WARNING]  APP SECURITY RISKS DETECTED!" -ForegroundColor Red
} else {
    Write-Host "Third-Party Apps Export Complete!" -ForegroundColor Green
}
Write-Host ("="*60) -ForegroundColor Cyan
Write-Host "`nResults saved to: $OutputFolder" -ForegroundColor Cyan
Write-Host ""
#endregion

