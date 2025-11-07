<#
.SYNOPSIS
    Export shared mailboxes, permissions, and usage statistics.

.DESCRIPTION
    Collects comprehensive shared mailbox data including:
    - Mailbox details (name, email, aliases)
    - Mailbox size and quota information
    - Permissions (Full Access, Send As, Send on Behalf)
    - Auto-reply and forwarding settings
    - Usage statistics and item counts

.PARAMETER OutputPath
    Path to save the exported data. Defaults to ../Data/[timestamp]/

.EXAMPLE
    .\03-Export-SharedMailboxes.ps1
    Export all shared mailbox data to default timestamped folder.

.NOTES
    Author: IT Audit
    Date: 2025-11-05
    Requires: ExchangeOnlineManagement module and active connection
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
Write-Host "     Microsoft 365 Shared Mailboxes Audit                  " -ForegroundColor Cyan
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

# Verify Exchange Online connection
try {
    $testConnection = Get-ConnectionInformation -ErrorAction Stop
    if ($testConnection.Count -eq 0) {
        throw "Not connected to Exchange Online"
    }
    Write-Host "[OK] Connected to Exchange Online`n" -ForegroundColor Green
} catch {
    Write-Error "Exchange Online connection required. Run 00-Connect-M365.ps1 first."
    exit 1
}

Write-Host "[1/5] Retrieving shared mailboxes..." -ForegroundColor Yellow

# Get all shared mailboxes
try {
    $sharedMailboxes = Get-Mailbox -RecipientTypeDetails SharedMailbox -ResultSize Unlimited
    Write-Host "  [OK] Found $($sharedMailboxes.Count) shared mailboxes" -ForegroundColor Green
} catch {
    Write-Error "Failed to retrieve shared mailboxes: $_"
    exit 1
}

if ($sharedMailboxes.Count -eq 0) {
    Write-Warning "No shared mailboxes found. Exiting."
    exit 0
}

Write-Host "`n[2/5] Retrieving mailbox statistics..." -ForegroundColor Yellow

$mailboxDetails = @()
$counter = 0
$total = $sharedMailboxes.Count

foreach ($mailbox in $sharedMailboxes) {
    $counter++
    $percentComplete = [math]::Round(($counter / $total) * 100)
    Write-Progress -Activity "Processing Shared Mailboxes" -Status "Mailbox $counter of $total ($percentComplete%)" -PercentComplete $percentComplete
    
    Write-Verbose "Processing mailbox: $($mailbox.DisplayName)" -Verbose
    
    # Get mailbox statistics
    try {
        $stats = Get-MailboxStatistics -Identity $mailbox.Identity -ErrorAction SilentlyContinue
        
        if ($stats) {
            $itemCount = if ($stats.ItemCount) { $stats.ItemCount } else { 0 }
            
            # Handle TotalItemSize with extra care
            if ($stats.TotalItemSize) {
                try {
                    if ($stats.TotalItemSize.Value) {
                        $totalItemSize = $stats.TotalItemSize.Value.ToMB()
                    } else {
                        $totalItemSize = 0
                    }
                } catch {
                    $totalItemSize = 0
                }
            } else {
                $totalItemSize = 0
            }
            
            $lastLogonTime = if ($stats.LastLogonTime) { $stats.LastLogonTime } else { $null }
        } else {
            $itemCount = 0
            $totalItemSize = 0
            $lastLogonTime = $null
        }
    } catch {
        $itemCount = 0
        $totalItemSize = 0
        $lastLogonTime = $null
    }
    
    # Get email addresses
    $primaryEmail = $mailbox.PrimarySmtpAddress
    $aliases = ($mailbox.EmailAddresses | Where-Object { $_ -like "smtp:*" -and $_ -notlike "SMTP:*" } | 
                ForEach-Object { $_ -replace "smtp:", "" }) -join "; "
    
    # Convert quota values
    $quotaWarning = if ($mailbox.IssueWarningQuota -and $mailbox.IssueWarningQuota -ne "Unlimited" -and $mailbox.IssueWarningQuota.Value) { 
        try {
            [math]::Round($mailbox.IssueWarningQuota.Value.ToMB() / 1024, 2)
        } catch {
            "Error"
        }
    } else { 
        "Unlimited" 
    }
    
    $quotaProhibitSend = if ($mailbox.ProhibitSendQuota -and $mailbox.ProhibitSendQuota -ne "Unlimited" -and $mailbox.ProhibitSendQuota.Value) { 
        try {
            [math]::Round($mailbox.ProhibitSendQuota.Value.ToMB() / 1024, 2)
        } catch {
            "Error"
        }
    } else { 
        "Unlimited" 
    }
    
    $quotaProhibitSendReceive = if ($mailbox.ProhibitSendReceiveQuota -and $mailbox.ProhibitSendReceiveQuota -ne "Unlimited" -and $mailbox.ProhibitSendReceiveQuota.Value) { 
        try {
            [math]::Round($mailbox.ProhibitSendReceiveQuota.Value.ToMB() / 1024, 2)
        } catch {
            "Error"
        }
    } else { 
        "Unlimited" 
    }
    
    # Calculate size in GB
    $sizeGB = [math]::Round($totalItemSize / 1024, 2)
    
    # Create mailbox object
    $mailboxObj = [PSCustomObject]@{
        'Display Name' = $mailbox.DisplayName
        'Primary Email' = $primaryEmail
        'Aliases' = $aliases
        'Organizational Unit' = $mailbox.OrganizationalUnit
        'Created Date' = $mailbox.WhenCreated
        'Last Logon' = $lastLogonTime
        'Item Count' = $itemCount
        'Size (GB)' = $sizeGB
        'Warning Quota (GB)' = $quotaWarning
        'Prohibit Send Quota (GB)' = $quotaProhibitSend
        'Prohibit Send/Receive Quota (GB)' = $quotaProhibitSendReceive
        'Auto Reply Enabled' = $mailbox.DeliverToMailboxAndForward
        'Forwarding Address' = $mailbox.ForwardingAddress
        'Forwarding SMTP Address' = $mailbox.ForwardingSMTPAddress
        'Hidden From Address Lists' = $mailbox.HiddenFromAddressListsEnabled
        'Mailbox GUID' = $mailbox.Guid
    }
    
    $mailboxDetails += $mailboxObj
}

Write-Progress -Activity "Processing Shared Mailboxes" -Completed
Write-Host "  [OK] Processed $counter shared mailboxes" -ForegroundColor Green

Write-Host "`n[3/5] Retrieving Full Access permissions..." -ForegroundColor Yellow

$fullAccessPermissions = @()
$counter = 0

foreach ($mailbox in $sharedMailboxes) {
    $counter++
    Write-Progress -Activity "Retrieving Full Access Permissions" -Status "Mailbox $counter of $total" -PercentComplete (($counter / $total) * 100)
    
    try {
        $permissions = Get-MailboxPermission -Identity $mailbox.Identity | 
            Where-Object { $_.User -notlike "NT AUTHORITY\*" -and $_.User -notlike "S-1-5-*" -and $_.IsInherited -eq $false }
        
        foreach ($perm in $permissions) {
            $fullAccessPermissions += [PSCustomObject]@{
                'Mailbox' = $mailbox.DisplayName
                'Mailbox Email' = $mailbox.PrimarySmtpAddress
                'User' = $perm.User
                'Access Rights' = ($perm.AccessRights -join ", ")
                'Deny' = $perm.Deny
            }
        }
    } catch {
        Write-Warning "Failed to get permissions for $($mailbox.DisplayName): $_"
    }
}

Write-Progress -Activity "Retrieving Full Access Permissions" -Completed
Write-Host "  [OK] Found $($fullAccessPermissions.Count) Full Access permission entries" -ForegroundColor Green

Write-Host "`n[4/5] Retrieving Send As permissions..." -ForegroundColor Yellow

$sendAsPermissions = @()
$counter = 0

foreach ($mailbox in $sharedMailboxes) {
    $counter++
    Write-Progress -Activity "Retrieving Send As Permissions" -Status "Mailbox $counter of $total" -PercentComplete (($counter / $total) * 100)
    
    try {
        $permissions = Get-RecipientPermission -Identity $mailbox.Identity | 
            Where-Object { $_.Trustee -notlike "NT AUTHORITY\*" -and $_.Trustee -notlike "S-1-5-*" }
        
        foreach ($perm in $permissions) {
            if ($perm.AccessRights -contains "SendAs") {
                $sendAsPermissions += [PSCustomObject]@{
                    'Mailbox' = $mailbox.DisplayName
                    'Mailbox Email' = $mailbox.PrimarySmtpAddress
                    'Trustee' = $perm.Trustee
                    'Access Rights' = ($perm.AccessRights -join ", ")
                }
            }
        }
    } catch {
        Write-Warning "Failed to get Send As permissions for $($mailbox.DisplayName): $_"
    }
}

Write-Progress -Activity "Retrieving Send As Permissions" -Completed
Write-Host "  [OK] Found $($sendAsPermissions.Count) Send As permission entries" -ForegroundColor Green

Write-Host "`n[5/5] Retrieving Send on Behalf permissions..." -ForegroundColor Yellow

$sendOnBehalfPermissions = @()

foreach ($mailbox in $sharedMailboxes) {
    if ($mailbox.GrantSendOnBehalfTo.Count -gt 0) {
        foreach ($user in $mailbox.GrantSendOnBehalfTo) {
            $sendOnBehalfPermissions += [PSCustomObject]@{
                'Mailbox' = $mailbox.DisplayName
                'Mailbox Email' = $mailbox.PrimarySmtpAddress
                'User' = $user
            }
        }
    }
}

Write-Host "  [OK] Found $($sendOnBehalfPermissions.Count) Send on Behalf permission entries" -ForegroundColor Green

# Export data
Write-Host "`n" + ("="*60) -ForegroundColor Cyan
Write-Host "Exporting data..." -ForegroundColor Cyan
Write-Host ("="*60) -ForegroundColor Cyan

$mailboxesFile = Join-Path $OutputPath "SharedMailboxes.csv"
$fullAccessFile = Join-Path $OutputPath "SharedMailboxes_FullAccess.csv"
$sendAsFile = Join-Path $OutputPath "SharedMailboxes_SendAs.csv"
$sendOnBehalfFile = Join-Path $OutputPath "SharedMailboxes_SendOnBehalf.csv"

$mailboxDetails | Export-Csv -Path $mailboxesFile -NoTypeInformation -Encoding UTF8
Write-Host "[OK] Shared mailboxes exported to: $mailboxesFile" -ForegroundColor Green

$fullAccessPermissions | Export-Csv -Path $fullAccessFile -NoTypeInformation -Encoding UTF8
Write-Host "[OK] Full Access permissions exported to: $fullAccessFile" -ForegroundColor Green

$sendAsPermissions | Export-Csv -Path $sendAsFile -NoTypeInformation -Encoding UTF8
Write-Host "[OK] Send As permissions exported to: $sendAsFile" -ForegroundColor Green

$sendOnBehalfPermissions | Export-Csv -Path $sendOnBehalfFile -NoTypeInformation -Encoding UTF8
Write-Host "[OK] Send on Behalf permissions exported to: $sendOnBehalfFile" -ForegroundColor Green

# Generate statistics
$totalSize = ($mailboxDetails | Measure-Object -Property 'Size (GB)' -Sum).Sum
$averageSize = [math]::Round($totalSize / $mailboxDetails.Count, 2)
$totalItems = ($mailboxDetails | Measure-Object -Property 'Item Count' -Sum).Sum

$largestMailboxes = $mailboxDetails | Sort-Object 'Size (GB)' -Descending | Select-Object -First 5
$inactiveMailboxes = $mailboxDetails | Where-Object { 
    $null -eq $_.'Last Logon' -or 
    (Get-Date) - [DateTime]$_.'Last Logon' -gt [TimeSpan]::FromDays(90) 
} | Sort-Object 'Last Logon'

$forwardingEnabled = $mailboxDetails | Where-Object { 
    $_.'Forwarding Address' -or $_.'Forwarding SMTP Address' 
}

# Generate summary report
$summary = @"
Shared Mailboxes Audit Summary
Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")

MAILBOX STATISTICS
==================
Total Shared Mailboxes:       $($mailboxDetails.Count)
Total Storage Used:            $([math]::Round($totalSize, 2)) GB
Average Storage per Mailbox:  $averageSize GB
Total Items:                   $totalItems

Largest Shared Mailboxes:
$($largestMailboxes | ForEach-Object { "  - $($_.'Display Name'): $($_.'Size (GB)') GB ($($_.'Item Count') items)" } | Out-String)

PERMISSIONS SUMMARY
===================
Full Access Permissions:       $($fullAccessPermissions.Count)
Send As Permissions:           $($sendAsPermissions.Count)
Send on Behalf Permissions:    $($sendOnBehalfPermissions.Count)

Unique Users with Full Access: $(($fullAccessPermissions | Select-Object -Unique 'User').Count)
Unique Users with Send As:     $(($sendAsPermissions | Select-Object -Unique 'Trustee').Count)

CONFIGURATION
=============
Hidden from Address Lists:     $(($mailboxDetails | Where-Object {$_.'Hidden From Address Lists' -eq $true}).Count)
With Forwarding Enabled:       $($forwardingEnabled.Count)
$(if ($forwardingEnabled.Count -gt 0) {
    "
Mailboxes with forwarding:
$($forwardingEnabled | ForEach-Object { "  - $($_.'Display Name') -> $($_.'Forwarding Address')$($_.'Forwarding SMTP Address')" } | Out-String)"
})

FINDINGS & RECOMMENDATIONS
==========================
$(if ($inactiveMailboxes.Count -gt 0) {
    "[WARNING] Warning: $($inactiveMailboxes.Count) shared mailboxes with no logon in last 90 days
Inactive mailboxes (consider review):
$($inactiveMailboxes | Select-Object -First 10 | ForEach-Object { "  - $($_.'Display Name'): Last logon $($_.'Last Logon') ($($_.'Size (GB)') GB)" } | Out-String)"
} else {
    "[OK] All shared mailboxes show recent activity"
})

$(if (($mailboxDetails | Where-Object {$_.'Size (GB)' -gt 25}).Count -gt 0) {
    "[WARNING] Warning: $(($mailboxDetails | Where-Object {$_.'Size (GB)' -gt 25}).Count) shared mailboxes over 25 GB"
})

$(if ($forwardingEnabled.Count -gt 0) {
    "[INFO] Information: $($forwardingEnabled.Count) shared mailboxes have forwarding enabled
Review forwarding rules for security compliance"
})

[INFO] Recommendation: Review permissions to ensure least privilege access
[INFO] Recommendation: Consider archiving policies for large mailboxes
[INFO] Recommendation: Review inactive mailboxes for potential deletion

FILES GENERATED
===============
- $mailboxesFile
- $fullAccessFile
- $sendAsFile
- $sendOnBehalfFile
- $($OutputPath)\SharedMailboxes-Summary.txt (this file)

NEXT STEPS
==========
1. Review permission assignments for least privilege
2. Investigate inactive mailboxes
3. Review and validate forwarding rules
4. Consider implementing retention policies for large mailboxes
5. Document business justification for each shared mailbox

"@

$summaryFile = Join-Path $OutputPath "SharedMailboxes-Summary.txt"
$summary | Out-File -FilePath $summaryFile -Encoding UTF8
Write-Host "[OK] Summary report: $summaryFile" -ForegroundColor Green

# Display summary to console
Write-Host "`n" + ("="*60) -ForegroundColor Cyan
Write-Host $summary -ForegroundColor White
Write-Host ("="*60) -ForegroundColor Cyan

Write-Host "`n[OK] Shared mailboxes audit complete!" -ForegroundColor Green
Write-Host "All data exported to: $OutputPath" -ForegroundColor Cyan

