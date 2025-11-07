# DNS Health Check Script (12-Check-DNSHealth.ps1)

## Overview
This PowerShell script performs comprehensive DNS health checks for Microsoft 365 domains, including email authentication records (SPF, DKIM, DMARC) and other critical DNS configurations.

## Features
- **Domain Resolution**: Checks A/AAAA record resolution
- **Mail Routing**: Validates MX records for email delivery
- **Email Authentication**:
  - SPF (Sender Policy Framework) validation and security analysis
  - DKIM (DomainKeys Identified Mail) record checking
  - DMARC (Domain-based Message Authentication) policy validation
- **DNSSEC**: Checks DNS Security Extensions status
- **Health Scoring**: Provides overall domain health score (0-100)
- **Automated Domain Discovery**: Can automatically get domains from M365 tenant

## Prerequisites
- PowerShell 5.1 or higher
- Internet connectivity for DNS lookups
- Microsoft Graph PowerShell module (for automatic domain discovery)

## Installation
Ensure required modules are installed:
```powershell
Install-Module Microsoft.Graph -Scope CurrentUser
```

## Usage

### Basic Usage (Automatic Domain Discovery)
```powershell
.\12-Check-DNSHealth.ps1
```
This will attempt to connect to Microsoft Graph and check all verified domains in your tenant.

### Manual Domain Specification
```powershell
.\12-Check-DNSHealth.ps1 -Domains "contoso.com", "fabrikam.com"
```

### Detailed Output
```powershell
.\12-Check-DNSHealth.ps1 -Domains "contoso.com" -Detailed
```

### Custom Output Path
```powershell
.\12-Check-DNSHealth.ps1 -OutputPath "..\Reports\DNS-Health-Report.csv"
```

## Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `Domains` | String[] | No | Auto-discover from M365 | Array of domain names to check |
| `OutputPath` | String | No | `..\Reports\DNS-Health-Report-[timestamp].csv` | Path for CSV output file |
| `Detailed` | Switch | No | False | Include detailed DNS record information |

## Output
The script generates a CSV file in the `..\Reports\` folder with the following columns:

### Standard Columns
- **Domain**: Domain name being checked
- **HealthScore**: Overall health score (0-100)
- **HealthStatus**: Health status (Excellent/Good/Fair/Poor/Critical)
- **DomainResolves**: Whether domain resolves (True/False)
- **HasMXRecords**: Whether MX records exist (True/False)
- **HasSPF**: Whether SPF record exists (True/False)
- **SPFRecord**: Raw SPF record text
- **SPFIissues**: SPF validation issues
- **DKIMExists**: Whether DKIM record exists (True/False)
- **DKIMSelector**: DKIM selector used
- **DKIMIssues**: DKIM validation issues
- **DMARCExists**: Whether DMARC record exists (True/False)
- **DMARCIssues**: DMARC validation issues
- **DNSSECEnabled**: Whether DNSSEC is enabled (True/False)
- **DNSSECIssues**: DNSSEC configuration issues
- **AllIssues**: Summary of all issues found
- **CheckedDate**: Timestamp of check

### Detailed Columns (when -Detailed is used)
- **MXRecords**: List of MX records with priorities
- **ARecords**: List of A records
- **AAAARecords**: List of AAAA records
- **DKIMRecord**: Raw DKIM record text
- **DMARCRecord**: Raw DMARC record text

## Health Scoring

### Score Ranges
- **Excellent (80-100)**: All critical records present and valid
- **Good (60-79)**: Most records present with minor issues
- **Fair (40-59)**: Some records missing or misconfigured
- **Poor (20-39)**: Multiple critical issues
- **Critical (0-19)**: Major configuration problems

### Scoring Breakdown
- Domain Resolution: 20 points
- MX Records: 15 points
- SPF Record: 15 points (+10 bonus for validity)
- DKIM Record: 15 points (+10 bonus for validity)
- DMARC Record: 15 points (+10 bonus for validity)
- DNSSEC: 10 points (optional but recommended)

## Common Issues Detected

### SPF Issues
- Missing or invalid SPF record
- Too permissive (+all instead of -all/~all)
- Exceeds DNS lookup limits (>10 lookups)
- Invalid syntax

### DKIM Issues
- Missing DKIM records for common selectors
- Invalid DKIM record format
- Missing public key or key type

### DMARC Issues
- Missing DMARC record
- Invalid policy values
- Incorrect record format

### DNS Issues
- Domain doesn't resolve
- Missing MX records
- DNSSEC misconfiguration

## Integration with M365 Audit Plan

This script complements the Microsoft 365 audit process by:

1. **Domain Discovery**: Automatically gets verified domains from tenant
2. **Email Security**: Validates email authentication setup
3. **Compliance**: Ensures DNS configurations meet security standards
4. **Reporting**: Provides structured output for audit documentation

## Best Practices

1. **Run Regularly**: Check DNS health quarterly or after DNS changes
2. **Monitor Scores**: Track health scores over time for trends
3. **Address Issues**: Fix critical issues promptly
4. **Document Changes**: Keep records of DNS configuration changes
5. **Test Changes**: Verify DNS changes don't break services

## Troubleshooting

### Authentication Issues
If automatic domain discovery fails:
```powershell
# Connect manually first
Connect-MgGraph -Scopes "Domain.Read.All"
.\12-Check-DNSHealth.ps1
```

### DNS Resolution Issues
- Ensure internet connectivity
- Check firewall/proxy settings
- Verify DNS server configuration

### Permission Issues
Ensure your account has:
- Domain.Read.All permission in Microsoft Graph
- Or specify domains manually with `-Domains` parameter

## Examples

### Check Single Domain with Details
```powershell
.\12-Check-DNSHealth.ps1 -Domains "contoso.com" -Detailed
```

### Monthly Health Check for Multiple Domains
```powershell
$domains = "contoso.com", "fabrikam.com", "tailspin.com"
.\12-Check-DNSHealth.ps1 -Domains $domains -OutputPath "Monthly-DNS-Health-$(Get-Date -Format 'yyyy-MM').csv"
```

### Automated Scheduled Check
```powershell
# PowerShell scheduled task example
$scriptPath = "C:\Scripts\12-Check-DNSHealth.ps1"
$outputPath = "C:\Reports\DNS-Health-$(Get-Date -Format 'yyyyMMdd').csv"
& $scriptPath -OutputPath $outputPath
```

## Related Scripts
- `00-Connect-M365.ps1`: Microsoft 365 connection setup
- `08-Export-EmailHygiene.ps1`: Email configuration audit
- `99-Generate-Report.ps1`: Consolidated reporting
