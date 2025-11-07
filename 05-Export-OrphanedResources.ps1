<#
.SYNOPSIS
    Export orphaned and inactive M365 resources.

.DESCRIPTION
    This script identifies resources without owners and inactive resources
    across Microsoft 365. This is critical for organizations that grew
    organically without formal IT management.

.PARAMETER OutputFolder
    Folder path for exported data. Defaults to ..\Data\[timestamp]

.PARAMETER InactiveDays
    Number of days to consider a resource inactive. Default: 90

.EXAMPLE
    .\05-Export-OrphanedResources.ps1
    Export orphaned resources with default settings.

.EXAMPLE
    .\05-Export-OrphanedResources.ps1 -OutputFolder "C:\Audit\Data" -InactiveDays 60
    Export with custom output folder and 60-day inactivity threshold.

.NOTES
    Author: IT Audit
    Date: 2025-11-05
    
    Prerequisites:
    - Run 00-Connect-M365.ps1 first to establish connections
    - Requires Microsoft.Graph, ExchangeOnlineManagement, MicrosoftTeams modules
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$OutputFolder,
    
    [Parameter(Mandatory=$false)]
    [int]$InactiveDays = 90
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
Write-Host "     Orphaned & Inactive Resources Export                  " -ForegroundColor Cyan
Write-Host "     IT Audit Toolkit                                      " -ForegroundColor Cyan
Write-Host "=============================================================" -ForegroundColor Cyan

Write-Host "`nInactive threshold: $InactiveDays days" -ForegroundColor Yellow
Write-Host "Output folder: $OutputFolder" -ForegroundColor Yellow
Write-Host ""

#region Groups Without Owners
Write-Host "[1/8] Exporting groups without owners..." -ForegroundColor Yellow

try {
    $allGroups = Get-MgGroup -All -Property Id,DisplayName,GroupTypes,Mail,CreatedDateTime
    $orphanedGroups = @()
    
    $groupCount = 0
    foreach ($group in $allGroups) {
        $groupCount++
        Write-Progress -Activity "Checking group owners" -Status "$groupCount of $($allGroups.Count)" -PercentComplete (($groupCount / $allGroups.Count) * 100)
        
        $owners = Get-MgGroupOwner -GroupId $group.Id -ErrorAction SilentlyContinue
        
        if ($null -eq $owners -or $owners.Count -eq 0) {
            $orphanedGroups += [PSCustomObject]@{
                GroupId = $group.Id
                DisplayName = $group.DisplayName
                GroupType = if ($group.GroupTypes -contains "Unified") { "Microsoft 365" } else { "Security/Distribution" }
                Email = $group.Mail
                CreatedDate = $group.CreatedDateTime
                Issue = "No owners assigned"
            }
        }
    }
    
    $orphanedGroups | Export-Csv -Path (Join-Path $OutputFolder "OrphanedGroups.csv") -NoTypeInformation
    Write-Host "  [OK] Found $($orphanedGroups.Count) groups without owners" -ForegroundColor Green
} catch {
    Write-Warning "Failed to export orphaned groups: $_"
}
#endregion

#region Teams Without Owners
Write-Host "[2/8] Exporting Teams without owners..." -ForegroundColor Yellow

try {
    $allTeams = Get-MgTeam -All -Property Id,DisplayName,Description,Visibility
    $orphanedTeams = @()

    $teamCount = 0
    foreach ($team in $allTeams) {
        $teamCount++
        Write-Progress -Activity "Checking team owners" -Status "$teamCount of $($allTeams.Count)" -PercentComplete (($teamCount / $allTeams.Count) * 100)

        $owners = Get-MgTeamMember -TeamId $team.Id -ErrorAction SilentlyContinue | Where-Object { $_.Roles -contains "owner" }

        if ($null -eq $owners -or $owners.Count -eq 0) {
            $orphanedTeams += [PSCustomObject]@{
                TeamId = $team.Id
                DisplayName = $team.DisplayName
                Description = $team.Description
                Visibility = $team.Visibility
                Issue = "No owners assigned"
            }
        }
    }
    
    $orphanedTeams | Export-Csv -Path (Join-Path $OutputFolder "OrphanedTeams.csv") -NoTypeInformation
    Write-Host "  [OK] Found $($orphanedTeams.Count) teams without owners" -ForegroundColor Green
} catch {
    Write-Warning "Failed to export orphaned teams: $_"
}
#endregion

#region Shared Mailboxes Without Delegates
Write-Host "[3/8] Exporting shared mailboxes without delegates..." -ForegroundColor Yellow

try {
    $sharedMailboxes = Get-Mailbox -RecipientTypeDetails SharedMailbox -ResultSize Unlimited
    $orphanedMailboxes = @()
    
    $mbxCount = 0
    foreach ($mailbox in $sharedMailboxes) {
        $mbxCount++
        Write-Progress -Activity "Checking mailbox permissions" -Status "$mbxCount of $($sharedMailboxes.Count)" -PercentComplete (($mbxCount / $sharedMailboxes.Count) * 100)
        
        $permissions = Get-MailboxPermission -Identity $mailbox.Identity | Where-Object {
            $_.User -ne "NT AUTHORITY\SELF" -and 
            $_.User -notlike "S-1-5-*" -and
            $_.IsInherited -eq $false
        }
        
        if ($null -eq $permissions -or $permissions.Count -eq 0) {
            $orphanedMailboxes += [PSCustomObject]@{
                DisplayName = $mailbox.DisplayName
                PrimarySmtpAddress = $mailbox.PrimarySmtpAddress
                WhenCreated = $mailbox.WhenCreated
                Issue = "No delegates assigned"
            }
        }
    }
    
    $orphanedMailboxes | Export-Csv -Path (Join-Path $OutputFolder "OrphanedSharedMailboxes.csv") -NoTypeInformation
    Write-Host "  [OK] Found $($orphanedMailboxes.Count) shared mailboxes without delegates" -ForegroundColor Green
} catch {
    Write-Warning "Failed to export orphaned shared mailboxes: $_"
}
#endregion

#region Inactive User Accounts
Write-Host "[4/8] Exporting inactive user accounts..." -ForegroundColor Yellow

try {
    $cutoffDate = (Get-Date).AddDays(-$InactiveDays)
    
    $inactiveUsers = Get-MgUser -All -Property Id,DisplayName,UserPrincipalName,AccountEnabled,CreatedDateTime,SignInActivity,AssignedLicenses | 
        Where-Object { 
            $_.AccountEnabled -eq $true -and (
                $null -eq $_.SignInActivity.LastSignInDateTime -or 
                $_.SignInActivity.LastSignInDateTime -lt $cutoffDate
            )
        } | Select-Object @{
            Name = "DisplayName"
            Expression = { $_.DisplayName }
        }, @{
            Name = "UserPrincipalName"
            Expression = { $_.UserPrincipalName }
        }, @{
            Name = "AccountEnabled"
            Expression = { $_.AccountEnabled }
        }, @{
            Name = "CreatedDate"
            Expression = { $_.CreatedDateTime }
        }, @{
            Name = "LastSignIn"
            Expression = { $_.SignInActivity.LastSignInDateTime }
        }, @{
            Name = "HasLicense"
            Expression = { $_.AssignedLicenses.Count -gt 0 }
        }, @{
            Name = "DaysSinceSignIn"
            Expression = { 
                if ($null -eq $_.SignInActivity.LastSignInDateTime) { 
                    "Never" 
                } else { 
                    [math]::Round(((Get-Date) - $_.SignInActivity.LastSignInDateTime).TotalDays, 0) 
                }
            }
        }
    
    $inactiveUsers | Export-Csv -Path (Join-Path $OutputFolder "InactiveUsers.csv") -NoTypeInformation
    Write-Host "  [OK] Found $($inactiveUsers.Count) inactive users (>$InactiveDays days)" -ForegroundColor Green
} catch {
    Write-Warning "Failed to export inactive users: $_"
}
#endregion

#region Inactive M365 Groups
Write-Host "[5/8] Exporting inactive Microsoft 365 Groups..." -ForegroundColor Yellow

try {
    # Get M365 Groups (Unified Groups)
    $m365Groups = Get-MgGroup -All -Filter "groupTypes/any(c:c eq 'Unified')" -Property Id,DisplayName,Mail,CreatedDateTime
    $inactiveGroups = @()
    
    $groupCount = 0
    foreach ($group in $m365Groups) {
        $groupCount++
        Write-Progress -Activity "Checking group activity" -Status "$groupCount of $($m365Groups.Count)" -PercentComplete (($groupCount / $m365Groups.Count) * 100)
        
        # Try to get the last activity from Microsoft Graph
        try {
            # Use the group's updatedDateTime as an approximation of last activity
            $lastActivity = $group.CreatedDateTime
            if ($group.AdditionalProperties -and $group.AdditionalProperties.updatedDateTime) {
                $lastActivity = [DateTime]::Parse($group.AdditionalProperties.updatedDateTime)
            }

            if ($lastActivity -lt $cutoffDate) {
                $inactiveGroups += [PSCustomObject]@{
                    GroupId = $group.Id
                    DisplayName = $group.DisplayName
                    Email = $group.Mail
                    CreatedDate = $group.CreatedDateTime
                    LastActivity = $lastActivity
                    DaysInactive = [math]::Round(((Get-Date) - $lastActivity).TotalDays, 0)
                }
            }
        } catch {
            # Silent continue
        }
    }
    
    $inactiveGroups | Export-Csv -Path (Join-Path $OutputFolder "InactiveM365Groups.csv") -NoTypeInformation
    Write-Host "  [OK] Found $($inactiveGroups.Count) inactive M365 Groups (>$InactiveDays days)" -ForegroundColor Green
} catch {
    Write-Warning "Failed to export inactive M365 Groups: $_"
}
#endregion

#region Inactive Teams
Write-Host "[6/8] Exporting inactive Teams..." -ForegroundColor Yellow

try {
    $teams = Get-MgTeam -All -Property Id,DisplayName,Description,Visibility
    $inactiveTeams = @()
    
    foreach ($team in $teams) {
        try {
            # Get the underlying M365 Group to check activity
            $group = Get-MgGroup -GroupId $team.Id -ErrorAction SilentlyContinue

            if ($null -ne $group) {
                $lastActivity = $group.CreatedDateTime
                if ($group.AdditionalProperties -and $group.AdditionalProperties.updatedDateTime) {
                    $lastActivity = [DateTime]::Parse($group.AdditionalProperties.updatedDateTime)
                }

                if ($lastActivity -lt $cutoffDate) {
                    $inactiveTeams += [PSCustomObject]@{
                        TeamId = $team.Id
                        DisplayName = $team.DisplayName
                        Description = $team.Description
                        Visibility = $team.Visibility
                        LastActivity = $lastActivity
                        DaysInactive = [math]::Round(((Get-Date) - $lastActivity).TotalDays, 0)
                    }
                }
            }
        } catch {
            # Silent continue
        }
    }
    
    $inactiveTeams | Export-Csv -Path (Join-Path $OutputFolder "InactiveTeams.csv") -NoTypeInformation
    Write-Host "  [OK] Found $($inactiveTeams.Count) inactive Teams (>$InactiveDays days)" -ForegroundColor Green
} catch {
    Write-Warning "Failed to export inactive Teams: $_"
}
#endregion

#region Inactive Shared Mailboxes
Write-Host "[7/8] Exporting inactive shared mailboxes..." -ForegroundColor Yellow

try {
    $sharedMailboxes = Get-Mailbox -RecipientTypeDetails SharedMailbox -ResultSize Unlimited
    $inactiveMailboxes = @()
    
    $mbxCount = 0
    foreach ($mailbox in $sharedMailboxes) {
        $mbxCount++
        Write-Progress -Activity "Checking mailbox activity" -Status "$mbxCount of $($sharedMailboxes.Count)" -PercentComplete (($mbxCount / $sharedMailboxes.Count) * 100)
        
        try {
            $stats = Get-MailboxStatistics -Identity $mailbox.Identity -ErrorAction SilentlyContinue
            
            if ($null -ne $stats) {
                $lastLogon = $stats.LastLogonTime
                
                if ($null -eq $lastLogon -or $lastLogon -lt $cutoffDate) {
                    $inactiveMailboxes += [PSCustomObject]@{
                        DisplayName = $mailbox.DisplayName
                        PrimarySmtpAddress = $mailbox.PrimarySmtpAddress
                        LastLogon = if ($null -eq $lastLogon) { "Never" } else { $lastLogon }
                        ItemCount = $stats.ItemCount
                        TotalItemSizeMB = [math]::Round(($stats.TotalItemSize.Value.ToBytes() / 1MB), 2)
                        DaysInactive = if ($null -eq $lastLogon) { "Never" } else { [math]::Round(((Get-Date) - $lastLogon).TotalDays, 0) }
                    }
                }
            }
        } catch {
            # Silent continue
        }
    }
    
    $inactiveMailboxes | Export-Csv -Path (Join-Path $OutputFolder "InactiveSharedMailboxes.csv") -NoTypeInformation
    Write-Host "  [OK] Found $($inactiveMailboxes.Count) inactive shared mailboxes (>$InactiveDays days)" -ForegroundColor Green
} catch {
    Write-Warning "Failed to export inactive shared mailboxes: $_"
}
#endregion

#region Summary Report
Write-Host "[8/8] Generating summary report..." -ForegroundColor Yellow

$summary = @"
Orphaned & Inactive Resources Audit Report
Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Inactive Threshold: $InactiveDays days

ORPHANED RESOURCES (No Owner/Delegate):
- Groups without owners: $($orphanedGroups.Count)
- Teams without owners: $($orphanedTeams.Count)
- Shared mailboxes without delegates: $($orphanedMailboxes.Count)

INACTIVE RESOURCES (>$InactiveDays days):
- Inactive user accounts: $($inactiveUsers.Count)
- Inactive M365 Groups: $($inactiveGroups.Count)
- Inactive Teams: $($inactiveTeams.Count)
- Inactive shared mailboxes: $($inactiveMailboxes.Count)

RECOMMENDATIONS:
1. Assign owners to orphaned groups and teams
2. Assign delegates to orphaned shared mailboxes
3. Review inactive accounts for license recovery
4. Archive or delete inactive resources after review
5. Implement governance policies to prevent future orphaned resources

"@

$summary | Out-File -FilePath (Join-Path $OutputFolder "OrphanedInactive-Summary.txt") -Encoding UTF8
Write-Host "  [OK] Summary report generated" -ForegroundColor Green

Write-Host "`n" + ("="*60) -ForegroundColor Cyan
Write-Host "Export Complete!" -ForegroundColor Green
Write-Host ("="*60) -ForegroundColor Cyan
Write-Host "`nResults saved to: $OutputFolder" -ForegroundColor Cyan
Write-Host ""
#endregion

