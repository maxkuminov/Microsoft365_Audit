#Requires -Version 5.1

<#
.SYNOPSIS
    Comprehensive DNS Health Check Script for Microsoft 365 Domains

.DESCRIPTION
    This script performs detailed DNS health checks including:
    - Basic domain resolution (A/AAAA records)
    - Mail routing (MX records)
    - Email authentication (SPF, DKIM, DMARC)
    - DNSSEC validation
    - Health scoring and recommendations

.PARAMETER Domains
    Array of domain names to check. If not specified, attempts to get domains from Microsoft 365 tenant.

.PARAMETER OutputPath
    Path to save the results. Defaults to ".\DNS-Health-Report-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"

.PARAMETER Detailed
    Include detailed DNS record information in output

.EXAMPLE
    .\12-Check-DNSHealth.ps1 -Domains "contoso.com", "fabrikam.com"

.EXAMPLE
    .\12-Check-DNSHealth.ps1 -Detailed -OutputPath "C:\Reports\DNS-Health.csv"

.NOTES
    Author: IT Audit Team
    Requires: PowerShell 5.1+, internet connectivity for DNS lookups
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string[]]$Domains,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "..\Reports\DNS-Health-Report-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv",

    [Parameter(Mandatory = $false)]
    [switch]$Detailed
)

# Function to perform DNS lookups
function Get-DNSRecord {
    param (
        [string]$Domain,
        [string]$Type,
        [string]$Server = $null
    )

    try {
        if ($Server) {
            $dnsResult = Resolve-DnsName -Name $Domain -Type $Type -Server $Server -ErrorAction Stop
        } else {
            $dnsResult = Resolve-DnsName -Name $Domain -Type $Type -ErrorAction Stop
        }
        return $dnsResult
    }
    catch {
        return $null
    }
}

# Function to validate SPF record
function Test-SPFRecord {
    param ([string]$SpfRecord)

    $issues = @()

    # Check for basic SPF structure
    if (-not ($SpfRecord -match '^"v=spf1')) {
        $issues += "SPF record doesn't start with 'v=spf1'"
    }

    # Check for common issues
    if ($SpfRecord -match '\s+\+all\s*$') {
        $issues += "SPF ends with +all (too permissive)"
    }

    if ($SpfRecord -match '\s+\?all\s*$') {
        $issues += "SPF ends with ?all (neutral - not recommended for security)"
    }

    if ($SpfRecord -notmatch '\s+-all\s*$|\s+~all\s*$') {
        $issues += "SPF should end with -all or ~all for proper security"
    }

    # Check for too many DNS lookups
    $lookupCount = 0
    $mechanisms = $SpfRecord -split '\s+'
    foreach ($mechanism in $mechanisms) {
        if ($mechanism -match '^(include|a|mx|ptr|exists):') {
            $lookupCount++
        }
    }

    if ($lookupCount -gt 10) {
        $issues += "SPF record exceeds 10 DNS lookups (RFC limit)"
    }

    return $issues
}

# Function to validate DKIM record
function Test-DKIMRecord {
    param ([string]$Domain, [string]$Selector = "selector1")

    $dkimDomain = "$Selector._domainkey.$Domain"
    $dkimRecord = Get-DNSRecord -Domain $dkimDomain -Type TXT

    if ($null -eq $dkimRecord) {
        return @{Exists = $false; Issues = @("DKIM record not found for selector '$Selector'")}
    }

    $recordText = $dkimRecord | Where-Object { $_.Type -eq 'TXT' } | Select-Object -First 1
    if ($null -eq $recordText) {
        return @{Exists = $false; Issues = @("DKIM TXT record not found")}
    }

    $dkimValue = $recordText.Strings -join ''
    $issues = @()

    # Basic DKIM validation
    if (-not ($dkimValue -match 'v=DKIM1')) {
        $issues += "DKIM record doesn't contain 'v=DKIM1'"
    }

    if (-not ($dkimValue -match 'k=')) {
        $issues += "DKIM record missing key type (k=)"
    }

    if (-not ($dkimValue -match 'p=')) {
        $issues += "DKIM record missing public key (p=)"
    }

    return @{
        Exists = $true
        Issues = $issues
        Record = $dkimValue
    }
}

# Function to validate DMARC record
function Test-DMARCRecord {
    param ([string]$Domain)

    $dmarcDomain = "_dmarc.$Domain"
    $dmarcRecord = Get-DNSRecord -Domain $dmarcDomain -Type TXT

    if ($null -eq $dmarcRecord) {
        return @{Exists = $false; Issues = @("DMARC record not found")}
    }

    $recordText = $dmarcRecord | Where-Object { $_.Type -eq 'TXT' } | Select-Object -First 1
    if ($null -eq $recordText) {
        return @{Exists = $false; Issues = @("DMARC TXT record not found")}
    }

    $dmarcValue = $recordText.Strings -join ''
    $issues = @()

    # Basic DMARC validation
    if (-not ($dmarcValue -match 'v=DMARC1')) {
        $issues += "DMARC record doesn't contain 'v=DMARC1'"
    }

    if (-not ($dmarcValue -match 'p=')) {
        $issues += "DMARC record missing policy (p=)"
    }

    # Check policy values
    if ($dmarcValue -match 'p=(\w+)') {
        $policy = $matches[1]
        if ($policy -notin @('none', 'quarantine', 'reject')) {
            $issues += "Invalid DMARC policy: $policy (should be none, quarantine, or reject)"
        }
    }

    return @{
        Exists = $true
        Issues = $issues
        Record = $dmarcValue
    }
}

# Function to check DNSSEC status
function Test-DNSSECStatus {
    param ([string]$Domain)

    try {
        # Check for DNSKEY records
        $dnskeyRecords = Get-DNSRecord -Domain $Domain -Type DNSKEY
        if ($null -eq $dnskeyRecords) {
            return @{Enabled = $false; Issues = @("No DNSKEY records found - DNSSEC not configured")}
        }

        # Check for DS records at parent
        $parentDomain = ($Domain -split '\.')[-2..-1] -join '.'
        $dsRecords = Get-DNSRecord -Domain $Domain -Type DS
        if ($null -eq $dsRecords) {
            return @{Enabled = $false; Issues = @("No DS records found - DNSSEC not properly delegated")}
        }

        return @{Enabled = $true; Issues = @()}
    }
    catch {
        return @{Enabled = $false; Issues = @("Error checking DNSSEC: $($_.Exception.Message)")}
    }
}

# Function to calculate health score
function Get-DNSHealthScore {
    param (
        [bool]$DomainResolves,
        [bool]$HasMX,
        [bool]$HasSPF,
        [object]$SPFIssues,
        [object]$DKIMResult,
        [object]$DMARCResult,
        [object]$DNSSECResult
    )

    $score = 0
    $maxScore = 100
    $issues = @()

    # Domain resolution (20 points)
    if ($DomainResolves) {
        $score += 20
    } else {
        $issues += "Domain does not resolve"
    }

    # MX records (15 points)
    if ($HasMX) {
        $score += 15
    } else {
        $issues += "No MX records found"
    }

    # SPF (15 points)
    if ($HasSPF) {
        $score += 15
        if ($SPFIssues.Count -eq 0) {
            $score += 10  # Bonus for valid SPF
        } else {
            $issues += "SPF issues: $($SPFIssues -join '; ')"
        }
    } else {
        $issues += "No SPF record found"
    }

    # DKIM (15 points)
    if ($DKIMResult.Exists) {
        $score += 15
        if ($DKIMResult.Issues.Count -eq 0) {
            $score += 10  # Bonus for valid DKIM
        } else {
            $issues += "DKIM issues: $($DKIMResult.Issues -join '; ')"
        }
    } else {
        $issues += "DKIM record not found"
    }

    # DMARC (15 points)
    if ($DMARCResult.Exists) {
        $score += 15
        if ($DMARCResult.Issues.Count -eq 0) {
            $score += 10  # Bonus for valid DMARC
        } else {
            $issues += "DMARC issues: $($DMARCResult.Issues -join '; ')"
        }
    } else {
        $issues += "DMARC record not found"
    }

    # DNSSEC (10 points - optional but recommended)
    if ($DNSSECResult.Enabled) {
        $score += 10
    } elseif ($DNSSECResult.Issues.Count -gt 0) {
        $issues += "DNSSEC: $($DNSSECResult.Issues[0])"
    }

    $healthStatus = switch ($score) {
        { $_ -ge 80 } { "Excellent"; break }
        { $_ -ge 60 } { "Good"; break }
        { $_ -ge 40 } { "Fair"; break }
        { $_ -ge 20 } { "Poor"; break }
        default { "Critical" }
    }

    return @{
        Score = $score
        Status = $healthStatus
        Issues = $issues
    }
}

# Main script logic
Write-Host "DNS Health Check Script for Microsoft 365" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# Get domains to check
$domainsToCheck = @()
if ($Domains) {
    $domainsToCheck = $Domains
} else {
    Write-Host "No domains specified. Attempting to get domains from Microsoft 365 tenant..." -ForegroundColor Yellow

    try {
        # Try to connect to Microsoft Graph if not already connected
        $context = Get-MgContext -ErrorAction SilentlyContinue
        if ($null -eq $context) {
            Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Yellow
            Connect-MgGraph -Scopes "Domain.Read.All" -ErrorAction Stop
        }

        $mgDomains = Get-MgDomain -ErrorAction Stop | Where-Object { $_.IsVerified -eq $true }
        $domainsToCheck = $mgDomains.Id

        Write-Host "Found $($domainsToCheck.Count) verified domains in tenant." -ForegroundColor Green
    }
    catch {
        Write-Host "Could not retrieve domains from Microsoft 365. Please specify domains manually using -Domains parameter." -ForegroundColor Red
        Write-Host "Example: .\12-Check-DNSHealth.ps1 -Domains 'contoso.com', 'fabrikam.com'" -ForegroundColor Yellow
        exit 1
    }
}

if ($domainsToCheck.Count -eq 0) {
    Write-Host "No domains to check. Exiting." -ForegroundColor Red
    exit 1
}

Write-Host "Checking DNS health for $($domainsToCheck.Count) domain(s)..." -ForegroundColor Green
Write-Host ""

# Initialize results array
$results = @()

foreach ($domain in $domainsToCheck) {
    Write-Host "Checking domain: $domain" -ForegroundColor Yellow

    # Basic domain resolution
    $aRecords = Get-DNSRecord -Domain $domain -Type A
    $aaaaRecords = Get-DNSRecord -Domain $domain -Type AAAA
    $domainResolves = ($null -ne $aRecords) -or ($null -ne $aaaaRecords)

    # MX records
    $mxRecords = Get-DNSRecord -Domain $domain -Type MX
    $hasMX = $null -ne $mxRecords

    # SPF record
    $spfRecords = Get-DNSRecord -Domain $domain -Type TXT | Where-Object {
        ($_.Strings -join '') -match '^"v=spf1'
    }
    $hasSPF = $null -ne $spfRecords
    $spfRecord = if ($hasSPF) { $spfRecords | Select-Object -First 1 | ForEach-Object { $_.Strings -join '' } } else { $null }
    $spfIssues = if ($hasSPF) { Test-SPFRecord -SpfRecord $spfRecord } else { @() }

    # DKIM record (check common selectors)
    $dkimSelectors = @("selector1", "selector2", "default", "google", "k1", "s1")
    $dkimResult = $null
    foreach ($selector in $dkimSelectors) {
        $dkimResult = Test-DKIMRecord -Domain $domain -Selector $selector
        if ($dkimResult.Exists) {
            break
        }
    }

    # DMARC record
    $dmarcResult = Test-DMARCRecord -Domain $domain

    # DNSSEC status
    $dnssecResult = Test-DNSSECStatus -Domain $domain

    # Calculate health score
    $healthScore = Get-DNSHealthScore -DomainResolves $domainResolves -HasMX $hasMX -HasSPF $hasSPF `
        -SPFIssues $spfIssues -DKIMResult $dkimResult -DMARCResult $dmarcResult -DNSSECResult $dnssecResult

    # Create result object
    $result = [PSCustomObject]@{
        Domain = $domain
        HealthScore = $healthScore.Score
        HealthStatus = $healthScore.Status
        DomainResolves = $domainResolves
        HasMXRecords = $hasMX
        HasSPF = $hasSPF
        SPFRecord = $spfRecord
        SPFIissues = ($spfIssues -join '; ')
        DKIMExists = $dkimResult.Exists
        DKIMSelector = if ($dkimResult.Exists) { $dkimSelectors[$dkimSelectors.IndexOf($selector)] } else { $null }
        DKIMIssues = ($dkimResult.Issues -join '; ')
        DMARCExists = $dmarcResult.Exists
        DMARCIssues = ($dmarcResult.Issues -join '; ')
        DNSSECEnabled = $dnssecResult.Enabled
        DNSSECIssues = ($dnssecResult.Issues -join '; ')
        AllIssues = ($healthScore.Issues -join '; ')
        CheckedDate = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    }

    if ($Detailed) {
        $result | Add-Member -MemberType NoteProperty -Name 'MXRecords' -Value ($mxRecords | ForEach-Object { "$($_.NameExchange) (Priority: $($_.Preference))" } | Where-Object { $_ } | Join-String -Separator '; ')
        $result | Add-Member -MemberType NoteProperty -Name 'ARecords' -Value ($aRecords | ForEach-Object { $_.IPAddress } | Where-Object { $_ } | Join-String -Separator '; ')
        $result | Add-Member -MemberType NoteProperty -Name 'AAAARecords' -Value ($aaaaRecords | ForEach-Object { $_.IPAddress } | Where-Object { $_ } | Join-String -Separator '; ')
        $result | Add-Member -MemberType NoteProperty -Name 'DKIMRecord' -Value $dkimResult.Record
        $result | Add-Member -MemberType NoteProperty -Name 'DMARCRecord' -Value $dmarcResult.Record
    }

    $results += $result

    $color = switch ($healthScore.Status) {
        "Excellent" { "Green" }
        "Good" { "Cyan" }
        "Fair" { "Yellow" }
        "Poor" { "Magenta" }
        "Critical" { "Red" }
        default { "White" }
    }
    Write-Host "  Health Score: $($healthScore.Score)/100 ($($healthScore.Status))" -ForegroundColor $color

    if ($healthScore.Issues.Count -gt 0) {
        Write-Host "  Issues: $($healthScore.Issues.Count)" -ForegroundColor Red
        foreach ($issue in $healthScore.Issues) {
            Write-Host "    - $issue" -ForegroundColor Red
        }
    }

    Write-Host ""
}

# Export results
Write-Host "Exporting results to: $OutputPath" -ForegroundColor Green
$results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

# Summary report
Write-Host ""
Write-Host "Summary Report:" -ForegroundColor Cyan
Write-Host "===============" -ForegroundColor Cyan

$excellentCount = 0
$goodCount = 0
$fairCount = 0
$poorCount = 0
$criticalCount = 0

foreach ($result in $results) {
    switch ($result.HealthStatus) {
        'Excellent' { $excellentCount++ }
        'Good' { $goodCount++ }
        'Fair' { $fairCount++ }
        'Poor' { $poorCount++ }
        'Critical' { $criticalCount++ }
    }
}

Write-Host "Domains checked: $($results.Count)" -ForegroundColor White
Write-Host "Excellent (80-100): $excellentCount" -ForegroundColor Green
Write-Host "Good (60-79): $goodCount" -ForegroundColor Cyan
Write-Host "Fair (40-59): $fairCount" -ForegroundColor Yellow
Write-Host "Poor (20-39): $poorCount" -ForegroundColor Magenta
Write-Host "Critical (0-19): $criticalCount" -ForegroundColor Red

$averageScore = [math]::Round(($results | Measure-Object -Property HealthScore -Average).Average, 1)
Write-Host ""
Write-Host "Average Health Score: $averageScore/100" -ForegroundColor White

Write-Host ""
Write-Host "Detailed results exported to: $OutputPath" -ForegroundColor Green
Write-Host ""
Write-Host "Script completed successfully!" -ForegroundColor Green
