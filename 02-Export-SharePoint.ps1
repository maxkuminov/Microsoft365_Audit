<#
.SYNOPSIS
    Export SharePoint Online sites, storage, and permissions.

.DESCRIPTION
    Collects comprehensive SharePoint data including:
    - All site collections (Team sites, Communication sites, OneDrive)
    - Storage usage and quotas
    - Site owners and administrators
    - Sharing settings and external access
    - Last activity dates
    - Template types

.PARAMETER OutputPath
    Path to save the exported data. Defaults to ../Data/[timestamp]/

.PARAMETER IncludeOneDrive
    Include OneDrive for Business sites in the export. Default is $true.

.EXAMPLE
    .\02-Export-SharePoint.ps1
    Export all SharePoint sites including OneDrive.

.EXAMPLE
    .\02-Export-SharePoint.ps1 -IncludeOneDrive:$false
    Export SharePoint sites only, excluding OneDrive.

.NOTES
    Author: IT Audit
    Date: 2025-11-05
    Requires: PnP.PowerShell module and active connection
    Run 00-Connect-M365.ps1 first to establish connections
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$OutputPath,
    
    [Parameter(Mandatory=$false)]
    [bool]$IncludeOneDrive = $true
)

$ErrorActionPreference = "Stop"

# Banner
Write-Host "=============================================================" -ForegroundColor Cyan
Write-Host "     Microsoft 365 SharePoint Sites Audit                  " -ForegroundColor Cyan
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

# Verify PnP connection
try {
    $connection = Get-PnPConnection -ErrorAction Stop
    Write-Host "[OK] Connected to: $($connection.Url)`n" -ForegroundColor Green
} catch {
    Write-Error "PnP PowerShell connection required. Run 00-Connect-M365.ps1 first."
    exit 1
}

Write-Host "[1/4] Retrieving SharePoint sites..." -ForegroundColor Yellow

# Get all site collections
try {
    if ($IncludeOneDrive) {
        $sites = Get-PnPTenantSite -IncludeOneDriveSites
        Write-Host "  [OK] Found $($sites.Count) sites (including OneDrive)" -ForegroundColor Green
    } else {
        $sites = Get-PnPTenantSite | Where-Object { $_.Template -notlike "*SPSPERS*" }
        Write-Host "  [OK] Found $($sites.Count) sites (excluding OneDrive)" -ForegroundColor Green
    }
} catch {
    Write-Error "Failed to retrieve sites: $_"
    exit 1
}

Write-Host "`n[2/4] Processing site details..." -ForegroundColor Yellow

$siteDetails = @()
$counter = 0
$total = $sites.Count

foreach ($site in $sites) {
    $counter++
    $percentComplete = [math]::Round(($counter / $total) * 100)
    Write-Progress -Activity "Processing Sites" -Status "Site $counter of $total ($percentComplete%)" -PercentComplete $percentComplete
    
    # Determine site type
    $siteType = switch -Wildcard ($site.Template) {
        "GROUP*" { "Microsoft 365 Group Site" }
        "SITEPAGEPUBLISHING*" { "Communication Site" }
        "STS*" { "Team Site" }
        "*SPSPERS*" { "OneDrive" }
        "TEAMCHANNEL*" { "Teams Private Channel" }
        default { $site.Template }
    }
    
    # Calculate storage percentage
    $storagePercentUsed = if ($site.StorageMaximumLevel -gt 0) {
        [math]::Round(($site.StorageUsageCurrent / $site.StorageMaximumLevel) * 100, 2)
    } else {
        0
    }
    
    # Convert storage to GB
    $storageUsedGB = [math]::Round($site.StorageUsageCurrent / 1024, 2)
    $storageQuotaGB = [math]::Round($site.StorageMaximumLevel / 1024, 2)
    
    # Sharing capability
    $sharingCapability = switch ($site.SharingCapability) {
        0 { "Disabled" }
        1 { "ExternalUserSharingOnly" }
        2 { "ExternalUserAndGuestSharing" }
        3 { "ExistingExternalUserSharingOnly" }
        default { "Unknown" }
    }
    
    # Create site object
    $siteObj = [PSCustomObject]@{
        'Site Title' = $site.Title
        'Site URL' = $site.Url
        'Site Type' = $siteType
        'Template' = $site.Template
        'Owner' = $site.Owner
        'Status' = $site.Status
        'Lock State' = $site.LockState
        'Storage Used (GB)' = $storageUsedGB
        'Storage Quota (GB)' = $storageQuotaGB
        'Storage % Used' = $storagePercentUsed
        'Last Content Modified' = $site.LastContentModifiedDate
        'Created Date' = $site.CreatedDate
        'Sharing Capability' = $sharingCapability
        'Allow Download' = $site.AllowDownloadingNonWebViewableFiles
        'Conditional Access Policy' = $site.ConditionalAccessPolicy
        'Sensitivity Label' = $site.SensitivityLabel
        'Hub Site ID' = $site.HubSiteId
        'Is Hub Site' = $site.IsHubSite
        'Group ID' = $site.GroupId
    }
    
    $siteDetails += $siteObj
}

Write-Progress -Activity "Processing Sites" -Completed
Write-Host "  [OK] Processed $counter sites" -ForegroundColor Green

Write-Host "`n[3/4] Retrieving tenant storage settings..." -ForegroundColor Yellow

# Get tenant information
try {
    $tenant = Get-PnPTenant
    
    $tenantInfo = [PSCustomObject]@{
        'Tenant Name' = $tenant.DisplayName
        'Sharing Capability' = $tenant.SharingCapability
        'Default Sharing Link Type' = $tenant.DefaultSharingLinkType
        'Default Link Permission' = $tenant.DefaultLinkPermission
        'OneDrive Storage Quota (GB)' = [math]::Round($tenant.OneDriveStorageQuota / 1024, 2)
        'Require Accept Terms' = $tenant.RequireAcceptingAccountMatchInvitedAccount
        'Prevent External Users From Resharing' = $tenant.PreventExternalUsersFromResharing
        'External Services Enabled' = $tenant.NotificationsInSharePointEnabled
        'Legacy Auth Protocols Enabled' = $tenant.LegacyAuthProtocolsEnabled
    }
    
    Write-Host "  [OK] Retrieved tenant settings" -ForegroundColor Green
} catch {
    Write-Warning "Could not retrieve tenant settings: $_"
    $tenantInfo = $null
}

Write-Host "`n[4/4] Generating site statistics..." -ForegroundColor Yellow

# Calculate statistics
$totalSites = $siteDetails.Count
$totalStorageUsed = ($siteDetails | Measure-Object -Property 'Storage Used (GB)' -Sum).Sum
$totalStorageQuota = ($siteDetails | Measure-Object -Property 'Storage Quota (GB)' -Sum).Sum
$averageStorageUsed = [math]::Round($totalStorageUsed / $totalSites, 2)

# Group by type
$sitesByType = $siteDetails | Group-Object 'Site Type' | 
    Select-Object Name, Count, @{N='Total Storage (GB)'; E={[math]::Round(($_.Group | Measure-Object -Property 'Storage Used (GB)' -Sum).Sum, 2)}} |
    Sort-Object Count -Descending

# Find sites with high storage usage
$highStorageSites = $siteDetails | Where-Object { $_.'Storage % Used' -gt 80 } | 
    Sort-Object 'Storage % Used' -Descending |
    Select-Object 'Site Title', 'Site URL', 'Storage Used (GB)', 'Storage Quota (GB)', 'Storage % Used' -First 10

# Find inactive sites (no activity in last 90 days)
$inactiveCutoff = (Get-Date).AddDays(-90)
$inactiveSites = $siteDetails | Where-Object { 
    $_.LastContentModifiedDate -and 
    [DateTime]$_.LastContentModifiedDate -lt $inactiveCutoff 
} | Sort-Object 'Last Content Modified' |
  Select-Object 'Site Title', 'Site URL', 'Last Content Modified', 'Storage Used (GB)' -First 10

Write-Host "  [OK] Statistics generated" -ForegroundColor Green

# Export data
Write-Host "`n" + ("="*60) -ForegroundColor Cyan
Write-Host "Exporting data..." -ForegroundColor Cyan
Write-Host ("="*60) -ForegroundColor Cyan

$sitesFile = Join-Path $OutputPath "SharePointSites.csv"
$tenantFile = Join-Path $OutputPath "SharePointTenant.csv"
$statsFile = Join-Path $OutputPath "SharePointStats.csv"

$siteDetails | Export-Csv -Path $sitesFile -NoTypeInformation -Encoding UTF8
Write-Host "[OK] Sites exported to: $sitesFile" -ForegroundColor Green

if ($tenantInfo) {
    $tenantInfo | Export-Csv -Path $tenantFile -NoTypeInformation -Encoding UTF8
    Write-Host "[OK] Tenant settings exported to: $tenantFile" -ForegroundColor Green
}

$sitesByType | Export-Csv -Path $statsFile -NoTypeInformation -Encoding UTF8
Write-Host "[OK] Statistics exported to: $statsFile" -ForegroundColor Green

# Generate summary report
$summary = @"
SharePoint Online Audit Summary
Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")

SITE STATISTICS
===============
Total Sites:                  $totalSites
Total Storage Used:           $([math]::Round($totalStorageUsed, 2)) GB
Total Storage Quota:          $([math]::Round($totalStorageQuota, 2)) GB
Average Storage per Site:     $averageStorageUsed GB
Storage Utilization:          $([math]::Round(($totalStorageUsed / $totalStorageQuota) * 100, 2))%

SITES BY TYPE
=============
$($sitesByType | ForEach-Object { "  $($_.Name): $($_.Count) sites ($($_.'Total Storage (GB)') GB)" } | Out-String)

SHARING & SECURITY
==================
$(if ($tenantInfo) {
    "Tenant Sharing: $($tenantInfo.'Sharing Capability')
Default Sharing Link: $($tenantInfo.'Default Sharing Link Type')
Prevent External Resharing: $($tenantInfo.'Prevent External Users From Resharing')"
} else {
    "Tenant information not available"
})

External Sharing Enabled:     $(($siteDetails | Where-Object {$_.'Sharing Capability' -ne 'Disabled'}).Count) sites
Sites with Sensitivity Label: $(($siteDetails | Where-Object {$_.'Sensitivity Label'}).Count) sites

HUB SITES
=========
Hub Sites:                    $(($siteDetails | Where-Object {$_.'Is Hub Site' -eq $true}).Count)
Sites Associated with Hubs:   $(($siteDetails | Where-Object {$_.'Hub Site ID'}).Count)

FINDINGS & RECOMMENDATIONS
==========================
$(if ($highStorageSites.Count -gt 0) {
    "[WARNING] Warning: $($highStorageSites.Count) sites using over 80% of storage quota
Top sites by storage utilization:
$($highStorageSites | ForEach-Object { "  - $($_.'Site Title'): $($_.'Storage % Used')% ($($_.'Storage Used (GB)') GB / $($_.'Storage Quota (GB)') GB)" } | Out-String)"
} else {
    "[OK] No sites approaching storage limits"
})

$(if ($inactiveSites.Count -gt 0) {
    "[WARNING] Warning: $($inactiveSites.Count) sites with no activity in last 90 days
Oldest inactive sites:
$($inactiveSites | ForEach-Object { "  - $($_.'Site Title'): Last modified $($_.'Last Content Modified') ($($_.'Storage Used (GB)') GB)" } | Out-String)"
} else {
    "[OK] No inactive sites detected"
})

$(if (($siteDetails | Where-Object {$_.'Sharing Capability' -eq 'ExternalUserAndGuestSharing'}).Count -gt 0) {
    "[INFO] Information: $(($siteDetails | Where-Object {$_.'Sharing Capability' -eq 'ExternalUserAndGuestSharing'}).Count) sites allow external user and guest sharing"
})

FILES GENERATED
===============
- $sitesFile
$(if ($tenantInfo) { "- $tenantFile" })
- $statsFile
- $($OutputPath)\SharePointInventory-Summary.txt (this file)

NEXT STEPS
==========
1. Review sites with high storage usage
2. Investigate inactive sites for potential archival
3. Review external sharing settings for compliance
4. Consider implementing retention policies
5. Review sites without sensitivity labels

"@

$summaryFile = Join-Path $OutputPath "SharePointInventory-Summary.txt"
$summary | Out-File -FilePath $summaryFile -Encoding UTF8
Write-Host "[OK] Summary report: $summaryFile" -ForegroundColor Green

# Display summary to console
Write-Host "`n" + ("="*60) -ForegroundColor Cyan
Write-Host $summary -ForegroundColor White
Write-Host ("="*60) -ForegroundColor Cyan

Write-Host "`n[OK] SharePoint audit complete!" -ForegroundColor Green
Write-Host "All data exported to: $OutputPath" -ForegroundColor Cyan

