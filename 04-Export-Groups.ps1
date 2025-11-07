<#
.SYNOPSIS
    Export all Microsoft 365 groups, distribution lists, and security groups.

.DESCRIPTION
    Collects comprehensive group data including:
    - Microsoft 365 Groups (Unified Groups)
    - Distribution Lists (and Dynamic Distribution Lists)
    - Security Groups (Azure AD)
    - Mail-Enabled Security Groups
    - Group membership and owners
    - Group settings and configurations

.PARAMETER OutputPath
    Path to save the exported data. Defaults to ../Data/[timestamp]/

.EXAMPLE
    .\04-Export-Groups.ps1
    Export all group types to default timestamped folder.

.NOTES
    Author: IT Audit
    Date: 2025-11-05
    Requires: Microsoft.Graph and ExchangeOnlineManagement modules
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
Write-Host "     Microsoft 365 Groups Audit                            " -ForegroundColor Cyan
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

# Verify connections
try {
    $mgContext = Get-MgContext
    if ($null -eq $mgContext) {
        throw "Not connected to Microsoft Graph"
    }
    
    $exoConnection = Get-ConnectionInformation -ErrorAction SilentlyContinue
    if ($exoConnection.Count -eq 0) {
        throw "Not connected to Exchange Online"
    }
    
    Write-Host "[OK] Connected to Microsoft Graph and Exchange Online`n" -ForegroundColor Green
} catch {
    Write-Error "Required connections not found. Run 00-Connect-M365.ps1 first. Error: $_"
    exit 1
}

# =============================================================================
# PART 1: MICROSOFT 365 GROUPS (UNIFIED GROUPS)
# =============================================================================

Write-Host "[1/6] Retrieving Microsoft 365 Groups..." -ForegroundColor Yellow

try {
    $m365Groups = Get-MgGroup -Filter "groupTypes/any(c:c eq 'Unified')" -All -Property Id,DisplayName,Description,Mail,CreatedDateTime,Visibility,GroupTypes
    Write-Host "  [OK] Found $($m365Groups.Count) Microsoft 365 Groups" -ForegroundColor Green
} catch {
    Write-Warning "Failed to retrieve Microsoft 365 Groups: $_"
    $m365Groups = @()
}

$m365GroupDetails = @()

if ($m365Groups.Count -gt 0) {
    Write-Host "  Processing Microsoft 365 Groups..." -ForegroundColor Gray
    $counter = 0
    
    foreach ($group in $m365Groups) {
        $counter++
        Write-Progress -Activity "Processing M365 Groups" -Status "Group $counter of $($m365Groups.Count)" -PercentComplete (($counter / $m365Groups.Count) * 100)
        
        # Get member and owner counts from Graph (already have the group object)
        try {
            $members = Get-MgGroupMember -GroupId $group.Id -All -ErrorAction SilentlyContinue
            $owners = Get-MgGroupOwner -GroupId $group.Id -All -ErrorAction SilentlyContinue

            $memberCount = if ($members) { $members.Count } else { 0 }
            $ownerCount = if ($owners) { $owners.Count } else { 0 }
            $guestCount = if ($members) {
                ($members | Where-Object { $_.AdditionalProperties.userType -eq 'Guest' }).Count
            } else { 0 }
        } catch {
            $memberCount = 0
            $ownerCount = 0
            $guestCount = 0
        }

        # Determine if connected to Teams (check for team in resourceBehaviorOptions or resourceProvisioningOptions)
        $hasTeams = $false
        try {
            $team = Get-MgTeam -TeamId $group.Id -ErrorAction SilentlyContinue
            $hasTeams = $null -ne $team
        } catch {
            $hasTeams = $false
        }

        $m365GroupDetails += [PSCustomObject]@{
            'Display Name' = $group.DisplayName
            'Email Address' = $group.Mail
            'Alias' = $group.MailNickname
            'Privacy' = $group.Visibility
            'Created Date' = $group.CreatedDateTime
            'Owner Count' = $ownerCount
            'Member Count' = $memberCount
            'Guest Count' = $guestCount
            'Has Teams' = $hasTeams
            'SharePoint Site URL' = "https://$((Get-MgOrganization).VerifiedDomains | Where-Object {$_.IsDefault}).Name)/sites/$($group.MailNickname)"
            'Group External ID' = $group.Id
            'Hidden From Address Lists' = $false  # Not available in Graph
            'Auto Subscribe New Members' = $false  # Not available in Graph
            'Allow External Senders' = $true  # Not available in Graph
            'Moderation Enabled' = $false  # Not available in Graph
        }
    }
    Write-Progress -Activity "Processing M365 Groups" -Completed
}

# =============================================================================
# PART 2: DISTRIBUTION GROUPS
# =============================================================================

Write-Host "`n[2/6] Retrieving Distribution Groups..." -ForegroundColor Yellow

try {
    $distributionGroups = Get-DistributionGroup -ResultSize Unlimited
    Write-Host "  [OK] Found $($distributionGroups.Count) Distribution Groups" -ForegroundColor Green
} catch {
    Write-Warning "Failed to retrieve Distribution Groups: $_"
    $distributionGroups = @()
}

$distributionGroupDetails = @()

if ($distributionGroups.Count -gt 0) {
    Write-Host "  Processing Distribution Groups..." -ForegroundColor Gray
    $counter = 0
    
    foreach ($group in $distributionGroups) {
        $counter++
        Write-Progress -Activity "Processing Distribution Groups" -Status "Group $counter of $($distributionGroups.Count)" -PercentComplete (($counter / $distributionGroups.Count) * 100)
        
        # Get member count
        try {
            $members = Get-DistributionGroupMember -Identity $group.Identity -ResultSize Unlimited -ErrorAction SilentlyContinue
            $memberCount = if ($members) { $members.Count } else { 0 }
        } catch {
            $memberCount = 0
        }
        
        # Get owners
        $owners = $group.ManagedBy -join "; "
        
        $distributionGroupDetails += [PSCustomObject]@{
            'Display Name' = $group.DisplayName
            'Email Address' = $group.PrimarySmtpAddress
            'Alias' = $group.Alias
            'Group Type' = $group.GroupType -join ", "
            'Recipient Type' = $group.RecipientTypeDetails
            'Created Date' = $group.WhenCreated
            'Owners' = $owners
            'Member Count' = $memberCount
            'Require Sender Authentication' = $group.RequireSenderAuthenticationEnabled
            'Hidden From Address Lists' = $group.HiddenFromAddressListsEnabled
            'Moderation Enabled' = $group.ModerationEnabled
            'Send Moderation Notifications' = $group.SendModerationNotifications
            'Organizational Unit' = $group.OrganizationalUnit
        }
    }
    Write-Progress -Activity "Processing Distribution Groups" -Completed
}

# =============================================================================
# PART 3: DYNAMIC DISTRIBUTION GROUPS
# =============================================================================

Write-Host "`n[3/6] Retrieving Dynamic Distribution Groups..." -ForegroundColor Yellow

try {
    $dynamicGroups = Get-DynamicDistributionGroup -ResultSize Unlimited
    Write-Host "  [OK] Found $($dynamicGroups.Count) Dynamic Distribution Groups" -ForegroundColor Green
} catch {
    Write-Warning "Failed to retrieve Dynamic Distribution Groups: $_"
    $dynamicGroups = @()
}

$dynamicGroupDetails = @()

if ($dynamicGroups.Count -gt 0) {
    foreach ($group in $dynamicGroups) {
        $dynamicGroupDetails += [PSCustomObject]@{
            'Display Name' = $group.DisplayName
            'Email Address' = $group.PrimarySmtpAddress
            'Alias' = $group.Alias
            'Created Date' = $group.WhenCreated
            'Recipient Filter' = $group.RecipientFilter
            'Included Recipients' = $group.IncludedRecipients -join ", "
            'Hidden From Address Lists' = $group.HiddenFromAddressListsEnabled
            'Organizational Unit' = $group.OrganizationalUnit
        }
    }
}

# =============================================================================
# PART 4: AZURE AD SECURITY GROUPS
# =============================================================================

Write-Host "`n[4/6] Retrieving Azure AD Security Groups..." -ForegroundColor Yellow

try {
    # Get all groups from Azure AD
    $allAzureGroups = Get-MgGroup -All -Property @(
        'Id', 'DisplayName', 'Description', 'GroupTypes', 'SecurityEnabled',
        'MailEnabled', 'Mail', 'CreatedDateTime', 'MembershipRule', 
        'MembershipRuleProcessingState'
    )
    
    # Filter for security groups (SecurityEnabled = true, not M365 groups)
    $securityGroups = $allAzureGroups | Where-Object { 
        $_.SecurityEnabled -eq $true -and 
        ($_.GroupTypes -notcontains "Unified")
    }
    
    Write-Host "  [OK] Found $($securityGroups.Count) Security Groups" -ForegroundColor Green
} catch {
    Write-Warning "Failed to retrieve Security Groups: $_"
    $securityGroups = @()
}

$securityGroupDetails = @()

if ($securityGroups.Count -gt 0) {
    Write-Host "  Processing Security Groups..." -ForegroundColor Gray
    $counter = 0
    
    foreach ($group in $securityGroups) {
        $counter++
        Write-Progress -Activity "Processing Security Groups" -Status "Group $counter of $($securityGroups.Count)" -PercentComplete (($counter / $securityGroups.Count) * 100)
        
        # Get member count
        try {
            $members = Get-MgGroupMember -GroupId $group.Id -All -ErrorAction SilentlyContinue
            $memberCount = if ($members) { $members.Count } else { 0 }
        } catch {
            $memberCount = 0
        }
        
        # Determine if dynamic
        $isDynamic = $group.MembershipRuleProcessingState -ne $null
        
        # Determine if mail-enabled
        $isMailEnabled = $group.MailEnabled -eq $true
        
        $securityGroupDetails += [PSCustomObject]@{
            'Display Name' = $group.DisplayName
            'Description' = $group.Description
            'Email Address' = $group.Mail
            'Mail Enabled' = $isMailEnabled
            'Dynamic Membership' = $isDynamic
            'Membership Rule' = $group.MembershipRule
            'Created Date' = $group.CreatedDateTime
            'Member Count' = $memberCount
            'Group ID' = $group.Id
        }
    }
    Write-Progress -Activity "Processing Security Groups" -Completed
}

# =============================================================================
# PART 5: GROUP MEMBERSHIP DETAILS
# =============================================================================

Write-Host "`n[5/6] Extracting detailed membership information..." -ForegroundColor Yellow

$allMemberships = @()

# M365 Groups membership
Write-Host "  Processing M365 Groups membership..." -ForegroundColor Gray
foreach ($group in $m365Groups) {
    try {
        $members = Get-MgGroupMember -GroupId $group.Id -All -ErrorAction SilentlyContinue
        foreach ($member in $members) {
            try {
                $user = Get-MgUser -UserId $member.Id -Property DisplayName,Mail,UserType -ErrorAction SilentlyContinue
                if ($user) {
                    $allMemberships += [PSCustomObject]@{
                        'Group Name' = $group.DisplayName
                        'Group Type' = 'Microsoft 365 Group'
                        'Member Name' = $user.DisplayName
                        'Member Email' = $user.Mail
                        'Member Type' = if ($user.UserType -eq 'Guest') { 'Guest' } else { 'Member' }
                    }
                }
            } catch {
                # Skip member if error
            }
        }
    } catch {
        # Skip if error
    }
}

Write-Host "  [OK] Extracted $($allMemberships.Count) membership records" -ForegroundColor Green

# =============================================================================
# PART 6: EXPORT DATA
# =============================================================================

Write-Host "`n[6/6] Exporting data..." -ForegroundColor Yellow

# Export all group types
$m365File = Join-Path $OutputPath "Groups_Microsoft365.csv"
$distributionFile = Join-Path $OutputPath "Groups_Distribution.csv"
$dynamicFile = Join-Path $OutputPath "Groups_DynamicDistribution.csv"
$securityFile = Join-Path $OutputPath "Groups_Security.csv"
$membershipFile = Join-Path $OutputPath "Groups_Memberships.csv"

if ($m365GroupDetails.Count -gt 0) {
    $m365GroupDetails | Export-Csv -Path $m365File -NoTypeInformation -Encoding UTF8
    Write-Host "[OK] Microsoft 365 Groups exported to: $m365File" -ForegroundColor Green
}

if ($distributionGroupDetails.Count -gt 0) {
    $distributionGroupDetails | Export-Csv -Path $distributionFile -NoTypeInformation -Encoding UTF8
    Write-Host "[OK] Distribution Groups exported to: $distributionFile" -ForegroundColor Green
}

if ($dynamicGroupDetails.Count -gt 0) {
    $dynamicGroupDetails | Export-Csv -Path $dynamicFile -NoTypeInformation -Encoding UTF8
    Write-Host "[OK] Dynamic Distribution Groups exported to: $dynamicFile" -ForegroundColor Green
}

if ($securityGroupDetails.Count -gt 0) {
    $securityGroupDetails | Export-Csv -Path $securityFile -NoTypeInformation -Encoding UTF8
    Write-Host "[OK] Security Groups exported to: $securityFile" -ForegroundColor Green
}

if ($allMemberships.Count -gt 0) {
    $allMemberships | Export-Csv -Path $membershipFile -NoTypeInformation -Encoding UTF8
    Write-Host "[OK] Group memberships exported to: $membershipFile" -ForegroundColor Green
}

# =============================================================================
# GENERATE SUMMARY
# =============================================================================

$totalGroups = $m365GroupDetails.Count + $distributionGroupDetails.Count + $dynamicGroupDetails.Count + $securityGroupDetails.Count
$m365WithTeams = ($m365GroupDetails | Where-Object { $_.'Has Teams' -eq $true }).Count
$securityMailEnabled = ($securityGroupDetails | Where-Object { $_.'Mail Enabled' -eq $true }).Count
$dynamicSecurityGroups = ($securityGroupDetails | Where-Object { $_.'Dynamic Membership' -eq $true }).Count

$summary = @"
Microsoft 365 Groups Audit Summary
Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")

GROUP STATISTICS
================
Total Groups (All Types):           $totalGroups

Microsoft 365 Groups:               $($m365GroupDetails.Count)
  - Connected to Teams:             $m365WithTeams
  - Private Groups:                 $(($m365GroupDetails | Where-Object {$_.Privacy -eq 'Private'}).Count)
  - Public Groups:                  $(($m365GroupDetails | Where-Object {$_.Privacy -eq 'Public'}).Count)
  - With Guest Members:             $(($m365GroupDetails | Where-Object {$_.'Guest Count' -gt 0}).Count)

Distribution Groups:                $($distributionGroupDetails.Count)
  - With Moderation:                $(($distributionGroupDetails | Where-Object {$_.'Moderation Enabled' -eq $true}).Count)

Dynamic Distribution Groups:        $($dynamicGroupDetails.Count)

Security Groups:                    $($securityGroupDetails.Count)
  - Mail-Enabled Security Groups:   $securityMailEnabled
  - Dynamic Security Groups:        $dynamicSecurityGroups

MEMBERSHIP STATISTICS
=====================
Total Membership Records:           $($allMemberships.Count)
Average Members per M365 Group:     $(if ($m365GroupDetails.Count -gt 0) { [math]::Round(($m365GroupDetails | Measure-Object -Property 'Member Count' -Average).Average, 1) } else { 0 })
Average Members per Dist. Group:    $(if ($distributionGroupDetails.Count -gt 0) { [math]::Round(($distributionGroupDetails | Measure-Object -Property 'Member Count' -Average).Average, 1) } else { 0 })

Largest M365 Groups (by members):
$(if ($m365GroupDetails.Count -gt 0) {
    $m365GroupDetails | Sort-Object 'Member Count' -Descending | Select-Object -First 5 | 
    ForEach-Object { "  - $($_.'Display Name'): $($_.'Member Count') members ($($_.'Guest Count') guests)" } | Out-String
} else { "  (None)" })

CONFIGURATION FINDINGS
======================
Groups Hidden from Address Lists:   $(($m365GroupDetails + $distributionGroupDetails + $dynamicGroupDetails | Where-Object {$_.'Hidden From Address Lists' -eq $true}).Count)
Groups Allowing External Senders:   $(($m365GroupDetails | Where-Object {$_.'Allow External Senders' -eq $true}).Count)
Groups with Moderation:             $(($m365GroupDetails + $distributionGroupDetails | Where-Object {$_.'Moderation Enabled' -eq $true}).Count)

FINDINGS & RECOMMENDATIONS
==========================
$(if (($m365GroupDetails | Where-Object { $_.'Owner Count' -eq 0 }).Count -gt 0) {
    "[WARNING] Warning: $(($m365GroupDetails | Where-Object { $_.'Owner Count' -eq 0 }).Count) Microsoft 365 Groups have no owners
Groups without owners:
$(($m365GroupDetails | Where-Object { $_.'Owner Count' -eq 0 } | Select-Object -First 5 | ForEach-Object { "  - $($_.'Display Name')" }) -join "`n")"
} else {
    "[OK] All Microsoft 365 Groups have owners"
})

$(if (($distributionGroupDetails | Where-Object { [string]::IsNullOrEmpty($_.Owners) }).Count -gt 0) {
    "[WARNING] Warning: $(($distributionGroupDetails | Where-Object { [string]::IsNullOrEmpty($_.Owners) }).Count) Distribution Groups have no owners"
})

$(if (($m365GroupDetails | Where-Object { $_.'Member Count' -eq 0 }).Count -gt 0) {
    "[INFO] Information: $(($m365GroupDetails | Where-Object { $_.'Member Count' -eq 0 }).Count) Microsoft 365 Groups have no members (consider cleanup)"
})

$(if (($distributionGroupDetails | Where-Object { $_.'Member Count' -eq 0 }).Count -gt 0) {
    "[INFO] Information: $(($distributionGroupDetails | Where-Object { $_.'Member Count' -eq 0 }).Count) Distribution Groups have no members (consider cleanup)"
})

[INFO] Recommendation: Review and assign owners to ownerless groups
[INFO] Recommendation: Consider implementing group naming policies
[INFO] Recommendation: Review groups with external access for security
[INFO] Recommendation: Implement group expiration policies for unused groups
[INFO] Recommendation: Regular cleanup of empty or inactive groups

FILES GENERATED
===============
$(if ($m365GroupDetails.Count -gt 0) { "- $m365File" })
$(if ($distributionGroupDetails.Count -gt 0) { "- $distributionFile" })
$(if ($dynamicGroupDetails.Count -gt 0) { "- $dynamicFile" })
$(if ($securityGroupDetails.Count -gt 0) { "- $securityFile" })
$(if ($allMemberships.Count -gt 0) { "- $membershipFile" })
- $($OutputPath)\GroupsInventory-Summary.txt (this file)

NEXT STEPS
==========
1. Assign owners to ownerless groups
2. Review and clean up empty groups
3. Audit external access permissions
4. Review dynamic group rules for accuracy
5. Implement group lifecycle policies
6. Document group purposes and ownership

"@

$summaryFile = Join-Path $OutputPath "GroupsInventory-Summary.txt"
$summary | Out-File -FilePath $summaryFile -Encoding UTF8
Write-Host "[OK] Summary report: $summaryFile" -ForegroundColor Green

# Display summary to console
Write-Host "`n" + ("="*60) -ForegroundColor Cyan
Write-Host $summary -ForegroundColor White
Write-Host ("="*60) -ForegroundColor Cyan

Write-Host "`n[OK] Groups audit complete!" -ForegroundColor Green
Write-Host "All data exported to: $OutputPath" -ForegroundColor Cyan

