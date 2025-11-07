<#
.SYNOPSIS
    Register a custom Entra ID application for PnP PowerShell authentication.

.DESCRIPTION
    This script registers a new Entra ID application in your tenant for use with PnP PowerShell.
    As of September 2024, the default PnP Management Shell app is no longer available,
    so each tenant must register their own app.
    
    The script will:
    1. Register a new Entra ID app with appropriate permissions
    2. Display the Client ID for use in other scripts
    3. Optionally set the Client ID as an environment variable

.PARAMETER ApplicationName
    The name for your Entra ID application. Default: "M365 Audit - PnP PowerShell"

.PARAMETER TenantDomain
    Your tenant domain (e.g., yourcompany.onmicrosoft.com)

.PARAMETER SetEnvironmentVariable
    If specified, sets the ENTRAID_CLIENT_ID environment variable for the current user.

.EXAMPLE
    .\00a-Register-PnP-App.ps1 -TenantDomain "yourcompany.onmicrosoft.com"
    Registers the app and displays the Client ID.

.EXAMPLE
    .\00a-Register-PnP-App.ps1 -TenantDomain "yourcompany.onmicrosoft.com" -SetEnvironmentVariable
    Registers the app and sets the Client ID as an environment variable.

.NOTES
    Author: IT Audit
    Date: 2025-11-05
    
    Required Modules:
    - PnP.PowerShell
    
    You must be a Global Administrator or Application Administrator to run this script.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$ApplicationName = "M365 Audit - PnP PowerShell",

    [Parameter(Mandatory=$true)]
    [string]$TenantDomain,

    [Parameter(Mandatory=$false)]
    [switch]$SetEnvironmentVariable = $false
)

# Set error action preference
$ErrorActionPreference = "Stop"

# ASCII Banner
Write-Host @"
+===========================================================+
|     PnP PowerShell - Entra ID App Registration            |
|     IT Audit Toolkit                                       |
+===========================================================+
"@ -ForegroundColor Cyan

Write-Host ""
Write-Host "This script will register a custom Entra ID application for PnP PowerShell." -ForegroundColor Yellow
Write-Host "You must be a Global Administrator or Application Administrator." -ForegroundColor Yellow
Write-Host ""

try {
    # Check if PnP.PowerShell module is installed
    Write-Host "[CHECK] Verifying PnP.PowerShell module..." -ForegroundColor Cyan
    $module = Get-Module -ListAvailable -Name PnP.PowerShell -ErrorAction SilentlyContinue
    if ($null -eq $module) {
        throw "PnP.PowerShell module is not installed. Please run: Install-Module -Name PnP.PowerShell -Scope CurrentUser"
    }
    Write-Host "  [OK] PnP.PowerShell module found (v$($module.Version))" -ForegroundColor Green

    # Register the Entra ID app
    Write-Host "`n[REGISTER] Creating Entra ID application..." -ForegroundColor Cyan
    Write-Host "  Application Name: $ApplicationName" -ForegroundColor Gray
    Write-Host "  Tenant: $TenantDomain" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  A browser window will open for authentication..." -ForegroundColor Yellow
    Write-Host ""

    # Define required permissions
    $sharePointDelegatePermissions = @(
        "AllSites.FullControl",
        "TermStore.ReadWrite.All",
        "User.ReadWrite.All"
    )

    $graphDelegatePermissions = @(
        "Group.ReadWrite.All",
        "User.ReadWrite.All",
        "Directory.ReadWrite.All"
    )

    # Register the app (browser-based authentication is automatic)
    $result = Register-PnPEntraIDAppForInteractiveLogin `
        -ApplicationName $ApplicationName `
        -Tenant $TenantDomain `
        -SharePointDelegatePermissions $sharePointDelegatePermissions `
        -GraphDelegatePermissions $graphDelegatePermissions

    # Extract Client ID from result
    # The cmdlet returns different property names depending on version
    $clientId = $null
    if ($result.'AzureAppId/ClientId') {
        $clientId = $result.'AzureAppId/ClientId'
    } elseif ($result.'Client ID') {
        $clientId = $result.'Client ID'
    } elseif ($result.ClientId) {
        $clientId = $result.ClientId
    } elseif ($result.AzureAppId) {
        $clientId = $result.AzureAppId
    }

    # If still null, try to parse from the output message
    if ([string]::IsNullOrWhiteSpace($clientId) -and $result.PSObject.Properties['AzureAppId/ClientId']) {
        $clientId = $result.PSObject.Properties['AzureAppId/ClientId'].Value
    }

    # Display success message and Client ID
    Write-Host "`n" + ("="*60) -ForegroundColor Green
    Write-Host "SUCCESS: Entra ID Application Registered!" -ForegroundColor Green
    Write-Host ("="*60) -ForegroundColor Green
    Write-Host ""
    Write-Host "Application Name: $ApplicationName" -ForegroundColor Cyan
    
    if ($clientId) {
        Write-Host "Client ID:        $clientId" -ForegroundColor Yellow
    } else {
        Write-Host "Client ID:        [See output above]" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  [WARN] Could not automatically extract Client ID" -ForegroundColor Yellow
        Write-Host "  Please copy the Application ID from the output above" -ForegroundColor Yellow
    }
    Write-Host ""

    # Save Client ID to file
    $configPath = Join-Path $PSScriptRoot "pnp-client-id.txt"
    $clientId | Out-File -FilePath $configPath -Encoding UTF8
    Write-Host "[SAVED] Client ID saved to: $configPath" -ForegroundColor Green
    Write-Host ""

    # Optionally set environment variable
    if ($SetEnvironmentVariable) {
        Write-Host "[ENV] Setting ENTRAID_CLIENT_ID environment variable..." -ForegroundColor Cyan
        [System.Environment]::SetEnvironmentVariable("ENTRAID_CLIENT_ID", $clientId, [EnvironmentVariableTarget]::User)
        Write-Host "  [OK] Environment variable set for current user" -ForegroundColor Green
        Write-Host "  [INFO] You may need to restart PowerShell for changes to take effect" -ForegroundColor Yellow
        Write-Host ""
    }

    # Display next steps
    Write-Host ("="*60) -ForegroundColor Cyan
    Write-Host "NEXT STEPS:" -ForegroundColor Cyan
    Write-Host ("="*60) -ForegroundColor Cyan
    Write-Host ""
    Write-Host "1. The Client ID has been saved to: $configPath" -ForegroundColor White
    Write-Host ""
    Write-Host "2. You can now run the connection script:" -ForegroundColor White
    Write-Host "   .\00-Connect-M365.ps1" -ForegroundColor Gray
    Write-Host ""
    Write-Host "3. The script will automatically use your registered app." -ForegroundColor White
    Write-Host ""

    if (-not $SetEnvironmentVariable) {
        Write-Host "TIP: To avoid storing the Client ID in a file, you can set it as" -ForegroundColor Yellow
        Write-Host "     an environment variable by running this script again with:" -ForegroundColor Yellow
        Write-Host "     -SetEnvironmentVariable" -ForegroundColor Gray
        Write-Host ""
    }

} catch {
    Write-Host "`n[ERROR] Failed to register Entra ID application" -ForegroundColor Red
    Write-Host "Error: $_" -ForegroundColor Red
    Write-Host ""
    Write-Host "[TROUBLESHOOTING]" -ForegroundColor Yellow
    Write-Host "1. Ensure you have Global Administrator or Application Administrator rights" -ForegroundColor Gray
    Write-Host "2. Verify your tenant domain is correct (e.g., yourtenant.onmicrosoft.com)" -ForegroundColor Gray
    Write-Host "3. Check your internet connection and firewall settings" -ForegroundColor Gray
    Write-Host "4. Ensure PnP.PowerShell module is up to date: Update-Module PnP.PowerShell" -ForegroundColor Gray
    exit 1
}

