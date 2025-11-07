<#
.SYNOPSIS
    Export device inventory and mobile device management data.

.DESCRIPTION
    This script identifies registered devices, stale devices, mobile devices,
    and compliance status. Critical for organizations without formal device
    management policies.

.PARAMETER OutputFolder
    Folder path for exported data. Defaults to ..\Data\[timestamp]

.PARAMETER StaleDays
    Number of days to consider a device stale. Default: 90

.EXAMPLE
    .\10-Export-Devices.ps1
    Export device data with default settings.

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
    [string]$OutputFolder,
    
    [Parameter(Mandatory=$false)]
    [int]$StaleDays = 90
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
Write-Host "     Device Inventory & Management Export                  " -ForegroundColor Cyan
Write-Host "     IT Audit Toolkit                                      " -ForegroundColor Cyan
Write-Host "=============================================================" -ForegroundColor Cyan

Write-Host "`nStale device threshold: $StaleDays days" -ForegroundColor Yellow
Write-Host "Output folder: $OutputFolder" -ForegroundColor Yellow
Write-Host ""

#region Azure AD Registered Devices
Write-Host "[1/4] Exporting Azure AD registered devices..." -ForegroundColor Yellow

try {
    $cutoffDate = (Get-Date).AddDays(-$StaleDays)
    $devices = Get-MgDevice -All -Property Id,DisplayName,OperatingSystem,OperatingSystemVersion,ApproximateLastSignInDateTime,TrustType,IsCompliant,IsManaged,RegisteredOwners
    
    $deviceReport = @()
    $deviceCount = 0
    
    foreach ($device in $devices) {
        $deviceCount++
        Write-Progress -Activity "Processing devices" -Status "$deviceCount of $($devices.Count)" -PercentComplete (($deviceCount / $devices.Count) * 100)
        
        try {
            # Get device owner
            $owners = Get-MgDeviceRegisteredOwner -DeviceId $device.Id -ErrorAction SilentlyContinue
            $ownerNames = @()
            foreach ($owner in $owners) {
                try {
                    $user = Get-MgUser -UserId $owner.Id -Property DisplayName -ErrorAction SilentlyContinue
                    if ($user) {
                        $ownerNames += $user.DisplayName
                    }
                } catch {
                    # Silent continue
                }
            }
            
            $lastSignIn = $device.ApproximateLastSignInDateTime
            $isStale = if ($null -eq $lastSignIn) { $true } else { $lastSignIn -lt $cutoffDate }
            
            $deviceReport += [PSCustomObject]@{
                DisplayName = $device.DisplayName
                DeviceId = $device.Id
                OperatingSystem = $device.OperatingSystem
                OSVersion = $device.OperatingSystemVersion
                TrustType = $device.TrustType
                IsCompliant = $device.IsCompliant
                IsManaged = $device.IsManaged
                LastSignIn = $lastSignIn
                DaysSinceSignIn = if ($null -eq $lastSignIn) { "Never" } else { [math]::Round(((Get-Date) - $lastSignIn).TotalDays, 0) }
                Owner = ($ownerNames -join '; ')
                IsStale = $isStale
                Issue = if ($isStale) { "Stale device (>$StaleDays days)" } elseif (-not $device.IsCompliant) { "Non-compliant" } elseif (-not $device.IsManaged) { "Unmanaged" } else { "" }
            }
        } catch {
            # Silent continue
        }
    }
    
    $deviceReport | Export-Csv -Path (Join-Path $OutputFolder "AzureADDevices.csv") -NoTypeInformation
    
    $staleDevices = ($deviceReport | Where-Object { $_.IsStale -eq $true }).Count
    $nonCompliant = ($deviceReport | Where-Object { $_.IsCompliant -eq $false }).Count
    $unmanaged = ($deviceReport | Where-Object { $_.IsManaged -eq $false }).Count
    
    Write-Host "  [OK] Found $($devices.Count) Azure AD devices" -ForegroundColor Cyan
    Write-Host "    - Stale devices (>$StaleDays days): $staleDevices" -ForegroundColor $(if($staleDevices -gt 0){'Yellow'}else{'Green'})
    Write-Host "    - Non-compliant devices: $nonCompliant" -ForegroundColor $(if($nonCompliant -gt 0){'Red'}else{'Green'})
    Write-Host "    - Unmanaged devices: $unmanaged" -ForegroundColor $(if($unmanaged -gt 0){'Yellow'}else{'Green'})
} catch {
    Write-Warning "Failed to export Azure AD devices: $_"
}
#endregion

#region Mobile Devices (Exchange ActiveSync)
Write-Host "[2/4] Exporting mobile devices (Exchange ActiveSync)..." -ForegroundColor Yellow

try {
    $mobileDevices = Get-MobileDevice -ResultSize Unlimited
    
    $mobileReport = $mobileDevices | Select-Object @{
        Name = "DeviceName"
        Expression = { $_.DeviceFriendlyName }
    }, @{
        Name = "DeviceType"
        Expression = { $_.DeviceType }
    }, @{
        Name = "DeviceModel"
        Expression = { $_.DeviceModel }
    }, @{
        Name = "DeviceOS"
        Expression = { $_.DeviceOS }
    }, @{
        Name = "UserDisplayName"
        Expression = { $_.UserDisplayName }
    }, @{
        Name = "FirstSyncTime"
        Expression = { $_.FirstSyncTime }
    }, @{
        Name = "DeviceAccessState"
        Expression = { $_.DeviceAccessState }
    }, @{
        Name = "DeviceAccessStateReason"
        Expression = { $_.DeviceAccessStateReason }
    }, @{
        Name = "Issue"
        Expression = { 
            if ($_.DeviceAccessState -eq "Blocked") { 
                "Device blocked" 
            } elseif ($_.DeviceAccessState -eq "Quarantined") { 
                "Device quarantined" 
            } else { 
                "" 
            }
        }
    }
    
    $mobileReport | Export-Csv -Path (Join-Path $OutputFolder "MobileDevices.csv") -NoTypeInformation
    
    $blockedDevices = ($mobileReport | Where-Object { $_.DeviceAccessState -eq "Blocked" }).Count
    $quarantinedDevices = ($mobileReport | Where-Object { $_.DeviceAccessState -eq "Quarantined" }).Count
    
    Write-Host "  [OK] Found $($mobileDevices.Count) mobile devices" -ForegroundColor Cyan
    Write-Host "    - Blocked devices: $blockedDevices" -ForegroundColor $(if($blockedDevices -gt 0){'Red'}else{'Green'})
    Write-Host "    - Quarantined devices: $quarantinedDevices" -ForegroundColor $(if($quarantinedDevices -gt 0){'Yellow'}else{'Green'})
} catch {
    Write-Warning "Failed to export mobile devices: $_"
}
#endregion

#region Device Summary by OS
Write-Host "[3/4] Generating device summary by operating system..." -ForegroundColor Yellow

try {
    $devicesByOS = $deviceReport | Group-Object -Property OperatingSystem | 
        Select-Object @{Name="OperatingSystem";Expression={$_.Name}}, Count | 
        Sort-Object -Property Count -Descending
    
    $devicesByOS | Export-Csv -Path (Join-Path $OutputFolder "DevicesByOperatingSystem.csv") -NoTypeInformation
    Write-Host "  [OK] Device summary by OS generated" -ForegroundColor Green
} catch {
    Write-Warning "Failed to generate OS summary: $_"
}
#endregion

#region Summary Report
Write-Host "[4/4] Generating device inventory summary..." -ForegroundColor Yellow

$summary = @"
Device Inventory & Management Audit Report
Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Stale Device Threshold: $StaleDays days

AZURE AD REGISTERED DEVICES:
- Total devices: $($devices.Count)
- Stale devices (>$StaleDays days): $staleDevices
- Non-compliant devices: $nonCompliant
- Unmanaged devices: $unmanaged

MOBILE DEVICES (ACTIVESYNC):
- Total mobile devices: $($mobileDevices.Count)
- Blocked devices: $blockedDevices
- Quarantined devices: $quarantinedDevices

DEVICES BY OPERATING SYSTEM:
$(foreach ($os in ($devicesByOS | Select-Object -First 10)) {
"  - $($os.OperatingSystem): $($os.Count)"
})

CRITICAL FINDINGS:
$(if($staleDevices -gt 10){"[WARNING]  $staleDevices stale devices should be reviewed for removal"}else{""})
$(if($nonCompliant -gt 0){"[WARNING]  $nonCompliant devices are non-compliant"}else{""})
$(if($unmanaged -gt ($devices.Count * 0.5)){"[WARNING]  More than 50% of devices are unmanaged"}else{""})
$(if($blockedDevices -gt 0){"[WARNING]  $blockedDevices mobile devices are blocked"}else{""})

RECOMMENDATIONS:
1. HIGH: Implement Mobile Device Management (MDM) policy
2. HIGH: Remove or disable stale device registrations (>$StaleDays days inactive)
3. MEDIUM: Address non-compliant devices
4. MEDIUM: Review and resolve blocked/quarantined mobile devices
5. MEDIUM: Implement Conditional Access policies requiring compliant devices
6. LOW: Regular device inventory reviews (quarterly)
7. LOW: Implement device naming standards
8. LOW: Track device ownership for accountability

DEVICE CLEANUP RECOMMENDATIONS:
- Devices not signed in for >$StaleDays days: $staleDevices devices
- Consider removing devices not used for >180 days
- Implement automated stale device cleanup policies

"@

$summary | Out-File -FilePath (Join-Path $OutputFolder "DeviceInventory-Summary.txt") -Encoding UTF8
Write-Host "  [OK] Device inventory summary generated" -ForegroundColor Green

Write-Host "`n" + ("="*60) -ForegroundColor Cyan
if ($staleDevices -gt 10 -or $nonCompliant -gt 0 -or $unmanaged -gt ($devices.Count * 0.5)) {
    Write-Host "[WARNING]  DEVICE MANAGEMENT ISSUES FOUND!" -ForegroundColor Yellow
} else {
    Write-Host "Device Inventory Export Complete!" -ForegroundColor Green
}
Write-Host ("="*60) -ForegroundColor Cyan
Write-Host "`nResults saved to: $OutputFolder" -ForegroundColor Cyan
Write-Host ""
#endregion

