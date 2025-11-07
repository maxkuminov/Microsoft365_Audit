<#
.SYNOPSIS
    Export permission sprawl and external sharing risks from M365.

.DESCRIPTION
    This script identifies oversharing, external access, anonymous links,
    and permission sprawl across SharePoint, OneDrive, and Teams. Critical
    for organizations without formal data governance.

.PARAMETER OutputFolder
    Folder path for exported data. Defaults to ..\Data\[timestamp]

.EXAMPLE
    .\07-Export-PermissionSprawl.ps1
    Export permission sprawl data with default settings.

.NOTES
    Author: IT Audit
    Date: 2025-11-05
    
    Prerequisites:
    - Run 00-Connect-M365.ps1 first to establish connections
    - Requires Microsoft.Graph, PnP.PowerShell modules
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
Write-Host "     Permission Sprawl & Oversharing Export                " -ForegroundColor Cyan
Write-Host "     IT Audit Toolkit                                      " -ForegroundColor Cyan
Write-Host "=============================================================" -ForegroundColor Cyan

Write-Host "`nOutput folder: $OutputFolder" -ForegroundColor Yellow
Write-Host ""

#region Guest Users
Write-Host "[1/6] Exporting guest user access..." -ForegroundColor Yellow

try {
    $guestUsers = Get-MgUser -All -Filter "userType eq 'Guest'" -Property Id,DisplayName,UserPrincipalName,Mail,CreatedDateTime,SignInActivity
    
    $guestReport = $guestUsers | Select-Object @{
        Name = "DisplayName"
        Expression = { $_.DisplayName }
    }, @{
        Name = "UserPrincipalName"
        Expression = { $_.UserPrincipalName }
    }, @{
        Name = "Email"
        Expression = { $_.Mail }
    }, @{
        Name = "InvitedDate"
        Expression = { $_.CreatedDateTime }
    }, @{
        Name = "LastSignIn"
        Expression = { $_.SignInActivity.LastSignInDateTime }
    }, @{
        Name = "Domain"
        Expression = { 
            if ($_.Mail) {
                $_.Mail.Split('@')[1]
            } else {
                "Unknown"
            }
        }
    }
    
    $guestReport | Export-Csv -Path (Join-Path $OutputFolder "GuestUsers.csv") -NoTypeInformation
    
    # Count guests by domain
    $guestsByDomain = $guestReport | Group-Object -Property Domain | 
        Select-Object @{Name="Domain";Expression={$_.Name}}, Count | 
        Sort-Object -Property Count -Descending
    
    $guestsByDomain | Export-Csv -Path (Join-Path $OutputFolder "GuestUsersByDomain.csv") -NoTypeInformation
    
    Write-Host "  [OK] Found $($guestUsers.Count) guest users from $($guestsByDomain.Count) domains" -ForegroundColor $(if($guestUsers.Count -gt 0){'Yellow'}else{'Green'})
} catch {
    Write-Warning "Failed to export guest users: $_"
}
#endregion

#region SharePoint External Sharing
Write-Host "[2/6] Checking SharePoint external sharing settings..." -ForegroundColor Yellow

try {
    # Get all SharePoint sites using PnP
    $sites = Get-PnPTenantSite
    
    $siteSharing = $sites | Select-Object @{
        Name = "SiteUrl"
        Expression = { $_.Url }
    }, @{
        Name = "Title"
        Expression = { $_.Title }
    }, @{
        Name = "Owner"
        Expression = { $_.Owner }
    }, @{
        Name = "SharingCapability"
        Expression = { $_.SharingCapability }
    }, @{
        Name = "Template"
        Expression = { $_.Template }
    }, @{
        Name = "StorageUsedMB"
        Expression = { [math]::Round($_.StorageUsageCurrent, 2) }
    }, @{
        Name = "LastContentModified"
        Expression = { $_.LastContentModifiedDate }
    }, @{
        Name = "Issue"
        Expression = { 
            if ($_.SharingCapability -eq "ExternalUserAndGuestSharing") {
                "Anonymous sharing enabled"
            } elseif ($_.SharingCapability -eq "ExternalUserSharingOnly") {
                "External sharing enabled"
            } else {
                ""
            }
        }
    }
    
    $siteSharing | Export-Csv -Path (Join-Path $OutputFolder "SharePointSiteSharing.csv") -NoTypeInformation
    
    $externalSharing = ($siteSharing | Where-Object { $_.SharingCapability -ne "Disabled" }).Count
    $anonymousSharing = ($siteSharing | Where-Object { $_.SharingCapability -eq "ExternalUserAndGuestSharing" }).Count
    
    Write-Host "  [OK] Checked $($sites.Count) SharePoint sites" -ForegroundColor Cyan
    Write-Host "    - External sharing enabled: $externalSharing" -ForegroundColor $(if($externalSharing -gt 0){'Yellow'}else{'Green'})
    Write-Host "    - Anonymous sharing enabled: $anonymousSharing" -ForegroundColor $(if($anonymousSharing -gt 0){'Red'}else{'Green'})
} catch {
    Write-Warning "Failed to check SharePoint sharing: $_"
}
#endregion

#region Sites with External Users
Write-Host "[3/6] Finding sites with external user access..." -ForegroundColor Yellow

try {
    $sitesWithExternalUsers = @()
    
    $siteCount = 0
    foreach ($site in $sites | Select-Object -First 50) { # Limit to first 50 for performance
        $siteCount++
        Write-Progress -Activity "Checking sites for external users" -Status "$siteCount of 50" -PercentComplete (($siteCount / 50) * 100)
        
        try {
            Connect-PnPOnline -Url $site.Url -Interactive -ErrorAction SilentlyContinue
            
            $externalUsers = Get-PnPUser | Where-Object { 
                $_.LoginName -like "*#ext#*" -or 
                $_.LoginName -like "*urn:spo:guest*"
            }
            
            if ($externalUsers.Count -gt 0) {
                foreach ($extUser in $externalUsers) {
                    $sitesWithExternalUsers += [PSCustomObject]@{
                        SiteUrl = $site.Url
                        SiteTitle = $site.Title
                        ExternalUserLoginName = $extUser.LoginName
                        ExternalUserEmail = $extUser.Email
                        ExternalUserTitle = $extUser.Title
                    }
                }
            }
        } catch {
            # Silent continue
        }
    }
    
    $sitesWithExternalUsers | Export-Csv -Path (Join-Path $OutputFolder "SitesWithExternalUsers.csv") -NoTypeInformation
    $uniqueSites = ($sitesWithExternalUsers | Select-Object -Property SiteUrl -Unique).Count
    
    Write-Host "  [OK] Found $($sitesWithExternalUsers.Count) external user assignments across $uniqueSites sites" -ForegroundColor $(if($sitesWithExternalUsers.Count -gt 0){'Yellow'}else{'Green'})
} catch {
    Write-Warning "Failed to find sites with external users: $_"
}
#endregion

#region Overly Permissive Groups
Write-Host "[4/6] Checking for overly permissive groups..." -ForegroundColor Yellow

try {
    $allGroups = Get-MgGroup -All -Property Id,DisplayName,GroupTypes,Visibility,CreatedDateTime
    
    $permissiveGroups = $allGroups | Where-Object {
        # Check for M365 Groups that are public
        ($_.GroupTypes -contains "Unified" -and $_.Visibility -eq "Public")
    } | Select-Object @{
        Name = "GroupName"
        Expression = { $_.DisplayName }
    }, @{
        Name = "GroupType"
        Expression = { if ($_.GroupTypes -contains "Unified") { "Microsoft 365" } else { "Security" } }
    }, @{
        Name = "Visibility"
        Expression = { $_.Visibility }
    }, @{
        Name = "CreatedDate"
        Expression = { $_.CreatedDateTime }
    }, @{
        Name = "Issue"
        Expression = { "Public visibility - anyone can join" }
    }
    
    $permissiveGroups | Export-Csv -Path (Join-Path $OutputFolder "OverlyPermissiveGroups.csv") -NoTypeInformation
    Write-Host "  [OK] Found $($permissiveGroups.Count) publicly visible groups" -ForegroundColor $(if($permissiveGroups.Count -gt 0){'Yellow'}else{'Green'})
} catch {
    Write-Warning "Failed to check permissive groups: $_"
}
#endregion

#region SharePoint Tenant Sharing Settings
Write-Host "[5/6] Checking tenant-level sharing settings..." -ForegroundColor Yellow

try {
    $tenantSettings = Get-PnPTenant
    
    $tenantSharing = [PSCustomObject]@{
        SharingCapability = $tenantSettings.SharingCapability
        DefaultSharingLinkType = $tenantSettings.DefaultSharingLinkType
        DefaultLinkPermission = $tenantSettings.DefaultLinkPermission
        RequireAnonymousLinksExpireInDays = $tenantSettings.RequireAnonymousLinksExpireInDays
        ExternalUserExpirationRequired = $tenantSettings.ExternalUserExpirationRequired
        ExternalUserExpireInDays = $tenantSettings.ExternalUserExpireInDays
        SharingDomainRestrictionMode = $tenantSettings.SharingDomainRestrictionMode
        SharingAllowedDomainList = ($tenantSettings.SharingAllowedDomainList -join '; ')
        SharingBlockedDomainList = ($tenantSettings.SharingBlockedDomainList -join '; ')
        OneDriveSharingCapability = $tenantSettings.OneDriveSharingCapability
        PreventExternalUsersFromResharing = $tenantSettings.PreventExternalUsersFromResharing
    }
    
    $tenantSharing | Export-Csv -Path (Join-Path $OutputFolder "TenantSharingSettings.csv") -NoTypeInformation
    Write-Host "  [OK] Tenant sharing settings exported" -ForegroundColor Green
    
    if ($tenantSettings.SharingCapability -eq "ExternalUserAndGuestSharing") {
        Write-Host "    [WARNING]  Anonymous sharing is enabled at tenant level" -ForegroundColor Red
    }
} catch {
    Write-Warning "Failed to check tenant sharing settings: $_"
}
#endregion

#region Summary Report
Write-Host "[6/6] Generating permission sprawl summary..." -ForegroundColor Yellow

$summary = @"
Permission Sprawl & Oversharing Audit Report
Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")

EXTERNAL ACCESS:
- Guest users in tenant: $($guestUsers.Count)
- Unique external domains: $($guestsByDomain.Count)
- Sites with external user access: $uniqueSites
- External user assignments: $($sitesWithExternalUsers.Count)

SHARING CONFIGURATION:
- SharePoint sites audited: $($sites.Count)
- Sites with external sharing: $externalSharing
- Sites with anonymous sharing: $anonymousSharing
- Publicly visible groups: $($permissiveGroups.Count)

TENANT SETTINGS:
- Tenant sharing capability: $($tenantSettings.SharingCapability)
- Default link type: $($tenantSettings.DefaultSharingLinkType)
- Anonymous link expiration: $(if($tenantSettings.RequireAnonymousLinksExpireInDays -gt 0){$tenantSettings.RequireAnonymousLinksExpireInDays + " days"}else{"Not required"})
- External user expiration: $(if($tenantSettings.ExternalUserExpirationRequired){"$($tenantSettings.ExternalUserExpireInDays) days"}else{"Not required"})

CRITICAL FINDINGS:
$(if($anonymousSharing -gt 0){"[WARNING]  $anonymousSharing sites allow anonymous sharing (anyone with link)"}else{""})
$(if($guestUsers.Count -gt 50){"[WARNING]  Large number of guest users ($($guestUsers.Count)) - review regularly"}else{""})
$(if($tenantSettings.RequireAnonymousLinksExpireInDays -eq 0){"[WARNING]  Anonymous links have no expiration policy"}else{""})
$(if($tenantSettings.PreventExternalUsersFromResharing -eq $false){"[WARNING]  External users can reshare content"}else{""})

RECOMMENDATIONS:
1. HIGH: Review all anonymous sharing links and set expiration
2. HIGH: Implement domain restrictions for external sharing
3. MEDIUM: Set anonymous link expiration policy (recommend 30-90 days)
4. MEDIUM: Enable external user expiration (recommend 90-180 days)
5. MEDIUM: Prevent external users from resharing
6. MEDIUM: Change publicly visible groups to private
7. LOW: Regular guest user access reviews (quarterly)
8. LOW: Implement sensitivity labels for data classification

"@

$summary | Out-File -FilePath (Join-Path $OutputFolder "PermissionSprawl-Summary.txt") -Encoding UTF8
Write-Host "  [OK] Permission sprawl summary generated" -ForegroundColor Green

Write-Host "`n" + ("="*60) -ForegroundColor Cyan
if ($anonymousSharing -gt 0 -or $tenantSettings.RequireAnonymousLinksExpireInDays -eq 0) {
    Write-Host "[WARNING]  OVERSHARING RISKS DETECTED!" -ForegroundColor Red
} else {
    Write-Host "Permission Sprawl Export Complete!" -ForegroundColor Green
}
Write-Host ("="*60) -ForegroundColor Cyan
Write-Host "`nResults saved to: $OutputFolder" -ForegroundColor Cyan
Write-Host ""
#endregion

