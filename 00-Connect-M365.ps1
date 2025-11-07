<#
.SYNOPSIS
    Connect to Microsoft 365 services for audit data collection.

.DESCRIPTION
    This script establishes connections to Microsoft Graph, Exchange Online, 
    SharePoint Online, and Microsoft Teams. It handles authentication and 
    verifies successful connection to each service.

.PARAMETER UseInteractive
    Use interactive authentication (browser-based login). Default is $true.

.PARAMETER TenantId
    Azure AD Tenant ID (optional for interactive auth).

.PARAMETER CertificateThumbprint
    Certificate thumbprint for app-only authentication (for automation).

.PARAMETER ApplicationId
    Application (Client) ID for app-only authentication.

.PARAMETER SharePointAdminUrl
    SharePoint Admin URL (optional). If not provided, will be auto-detected from your tenant.
    The script will first look for your .onmicrosoft.com domain for accurate detection.
    Example: https://yourtenant-admin.sharepoint.com
    
    If auto-detection fails, you'll be prompted to enter the correct URL.

.EXAMPLE
    .\00-Connect-M365.ps1
    Connect using interactive authentication with auto-detected SharePoint URL.
    The script will detect your tenant's .onmicrosoft.com domain for accurate URL detection.

.EXAMPLE
    .\00-Connect-M365.ps1 -SharePointAdminUrl "https://yourtenant-admin.sharepoint.com"
    Connect with a specific SharePoint Admin URL (useful if auto-detection is incorrect).

.EXAMPLE
    .\00-Connect-M365.ps1 -ApplicationId "xxx" -CertificateThumbprint "xxx" -TenantId "xxx"
    Connect using certificate-based authentication for automation.

.NOTES
    Author: IT Audit
    Date: 2025-11-05
    
    Required Modules:
    - Microsoft.Graph
    - ExchangeOnlineManagement
    - PnP.PowerShell
    - MicrosoftTeams
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [switch]$UseInteractive = $true,

    [Parameter(Mandatory=$false)]
    [string]$TenantId,

    [Parameter(Mandatory=$false)]
    [string]$CertificateThumbprint,

    [Parameter(Mandatory=$false)]
    [string]$ApplicationId,

    [Parameter(Mandatory=$false)]
    [string]$SharePointAdminUrl
)

# Set error action preference
$ErrorActionPreference = "Stop"

# Function to check PowerShell environment
function Test-PowerShellEnvironment {
    Write-Host "`n[ENV] Checking PowerShell environment..." -ForegroundColor Yellow

    # Check if running in interactive mode
    $isInteractive = [Environment]::UserInteractive
    Write-Host "  Interactive session: $isInteractive" -ForegroundColor Gray

    # Check PowerShell version
    $psVersion = $PSVersionTable.PSVersion
    Write-Host "  PowerShell version: $($psVersion.Major).$($psVersion.Minor)" -ForegroundColor Gray

    # Check execution policy
    $executionPolicy = Get-ExecutionPolicy
    Write-Host "  Execution policy: $executionPolicy" -ForegroundColor Gray

    # Check if running as administrator
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    Write-Host "  Running as administrator: $isAdmin" -ForegroundColor Gray

    return $true
}

# ASCII Banner
Write-Host @"
+===========================================================+
|     Microsoft 365 Audit - Connection Manager              |
|     IT Audit Toolkit                                       |
+===========================================================+
"@ -ForegroundColor Cyan

# Function to check if module is installed
function Test-ModuleInstalled {
    param([string]$ModuleName)

    try {
        # Check if module is available (don't import yet to avoid hangs)
        $module = Get-Module -ListAvailable -Name $ModuleName -ErrorAction Stop
        if ($null -eq $module) {
            Write-Warning "Module '$ModuleName' is not installed."
            return $false
        }

        # Just verify the module exists, don't import during check phase
        # Import will happen later when actually needed
        Write-Host "  [OK] $ModuleName is available (v$($module.Version))" -ForegroundColor Green
        return $true
    } catch {
        Write-Warning "Module '$ModuleName' check failed: $_"
        return $false
    }
}

# Function to install missing modules
function Install-RequiredModules {
    Write-Host "`n[SETUP] Checking required PowerShell modules..." -ForegroundColor Yellow
    
    $requiredModules = @(
        "Microsoft.Graph",
        "ExchangeOnlineManagement",
        "PnP.PowerShell",
        "MicrosoftTeams"
    )
    
    $missingModules = @()
    
    foreach ($module in $requiredModules) {
        if (-not (Test-ModuleInstalled -ModuleName $module)) {
            $missingModules += $module
        } else {
            Write-Host "  [OK] $module is installed" -ForegroundColor Green
        }
    }
    
    if ($missingModules.Count -gt 0) {
        Write-Host "`nMissing modules detected:" -ForegroundColor Yellow
        $missingModules | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
        
        $install = Read-Host "`nWould you like to install missing modules? (Y/N)"
        if ($install -eq "Y" -or $install -eq "y") {
            foreach ($module in $missingModules) {
                Write-Host "Installing $module..." -ForegroundColor Cyan
                try {
                    Install-Module -Name $module -Scope CurrentUser -Force -AllowClobber
                    Write-Host "  [OK] $module installed successfully" -ForegroundColor Green

                    # Import the newly installed module
                    Write-Host "  Importing $module..." -ForegroundColor Cyan
                    Import-Module -Name $module -Force -ErrorAction Stop
                    Write-Host "  [OK] $module imported successfully" -ForegroundColor Green
                } catch {
                    Write-Error "Failed to install/import $module : $_"
                    return $false
                }
            }
        } else {
            Write-Error "Cannot proceed without required modules."
            return $false
        }
    }
    
    return $true
}

# Function to connect to Microsoft Graph
function Connect-ToMicrosoftGraph {
    Write-Host "`n[1/4] Connecting to Microsoft Graph..." -ForegroundColor Yellow

    try {
        # Check for existing connection
        $existingContext = Get-MgContext -ErrorAction SilentlyContinue
        if ($existingContext -and $existingContext.Account) {
            Write-Host "  [INFO] Already connected to Microsoft Graph" -ForegroundColor Cyan
            Write-Host "    Tenant: $($existingContext.TenantId)" -ForegroundColor Gray
            Write-Host "    Account: $($existingContext.Account)" -ForegroundColor Gray
            return $true
        }

        if ($UseInteractive) {
            # Interactive authentication with required scopes
            $scopes = @(
                "User.Read.All",
                "Group.Read.All",
                "Directory.Read.All",
                "Sites.Read.All",
                "Organization.Read.All",
                "Policy.Read.All",
                "Application.Read.All",
                "Domain.Read.All",
                "Team.ReadBasic.All",
                "TeamSettings.Read.All",
                "AuditLog.Read.All"
            )

            # Add error handling for interactive auth in non-interactive environments
            $connectParams = @{
                Scopes = $scopes
                NoWelcome = $true
                ErrorAction = 'Stop'
            }

            Connect-MgGraph @connectParams
        } else {
            # Certificate-based authentication
            if ([string]::IsNullOrEmpty($ApplicationId) -or [string]::IsNullOrEmpty($CertificateThumbprint) -or [string]::IsNullOrEmpty($TenantId)) {
                throw "ApplicationId, CertificateThumbprint, and TenantId are required for non-interactive authentication."
            }

            $connectParams = @{
                ClientId = $ApplicationId
                TenantId = $TenantId
                CertificateThumbprint = $CertificateThumbprint
                NoWelcome = $true
                ErrorAction = 'Stop'
            }

            Connect-MgGraph @connectParams
        }

        # Verify connection with retry
        $maxRetries = 3
        $retryCount = 0
        $context = $null

        while ($retryCount -lt $maxRetries -and $null -eq $context) {
            try {
                $context = Get-MgContext
                if ($context -and $context.Account) {
                    break
                }
            } catch {
                Write-Host "  [RETRY] Attempting to verify connection (attempt $($retryCount + 1)/$maxRetries)..." -ForegroundColor Yellow
                Start-Sleep -Seconds 2
            }
            $retryCount++
        }

        if ($null -eq $context -or -not $context.Account) {
            throw "Failed to verify Microsoft Graph connection after $maxRetries attempts"
        }

        Write-Host "  [OK] Connected to Microsoft Graph" -ForegroundColor Green
        Write-Host "    Tenant: $($context.TenantId)" -ForegroundColor Gray
        Write-Host "    Account: $($context.Account)" -ForegroundColor Gray

        return $true
    } catch {
        Write-Error "Failed to connect to Microsoft Graph: $_"
        return $false
    }
}

# Function to connect to Exchange Online
function Connect-ToExchangeOnline {
    Write-Host "`n[2/4] Connecting to Exchange Online..." -ForegroundColor Yellow

    try {
        # Check for existing connection
        $existingConnection = Get-ConnectionInformation -ErrorAction SilentlyContinue
        if ($existingConnection) {
            Write-Host "  [INFO] Already connected to Exchange Online" -ForegroundColor Cyan
            Write-Host "    Organization: $($existingConnection.Name)" -ForegroundColor Gray
            return $true
        }

        if ($UseInteractive) {
            Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
        } else {
            # Use cached organization info if available
            if ($script:CachedOrganization) {
                $org = ($script:CachedOrganization.VerifiedDomains | Where-Object {$_.IsDefault}).Name
            } else {
                $org = (Get-MgOrganization).VerifiedDomains | Where-Object {$_.IsDefault} | Select-Object -ExpandProperty Name
            }
            Connect-ExchangeOnline -AppId $ApplicationId -CertificateThumbprint $CertificateThumbprint -Organization $org -ShowBanner:$false -ErrorAction Stop
        }

        # Verify connection with retry
        $maxRetries = 3
        $retryCount = 0
        $session = $null

        while ($retryCount -lt $maxRetries -and $null -eq $session) {
            try {
                $session = Get-ConnectionInformation | Select-Object -First 1
                if ($session) {
                    break
                }
            } catch {
                Write-Host "  [RETRY] Attempting to verify Exchange connection (attempt $($retryCount + 1)/$maxRetries)..." -ForegroundColor Yellow
                Start-Sleep -Seconds 2
            }
            $retryCount++
        }

        if ($null -eq $session) {
            throw "Failed to verify Exchange Online connection after $maxRetries attempts"
        }

        Write-Host "  [OK] Connected to Exchange Online" -ForegroundColor Green
        Write-Host "    Organization: $($session.Name)" -ForegroundColor Gray

        return $true
    } catch {
        Write-Error "Failed to connect to Exchange Online: $_"
        return $false
    }
}

# Function to connect to SharePoint Online
function Connect-ToSharePointOnline {
    Write-Host "`n[3/4] Connecting to SharePoint Online..." -ForegroundColor Yellow

    try {
        # Clear any stale connections first
        try {
            $existingConnection = Get-PnPConnection -ErrorAction SilentlyContinue
            if ($existingConnection) {
                Write-Host "  [INFO] Disconnecting from existing session..." -ForegroundColor Cyan
                Disconnect-PnPOnline -ErrorAction SilentlyContinue
            }
        } catch {
            # Ignore errors from checking/clearing stale connections
        }

        # Determine SharePoint Admin URL
        if (-not [string]::IsNullOrEmpty($SharePointAdminUrl)) {
            # Use provided URL
            $adminUrl = $SharePointAdminUrl
            Write-Host "  [INFO] Using provided SharePoint Admin URL: $adminUrl" -ForegroundColor Gray
        } else {
            # Attempt auto-detection from Microsoft Graph
            Write-Host "  [INFO] Auto-detecting SharePoint Admin URL..." -ForegroundColor Gray
            
            if ($script:CachedOrganization) {
                $org = $script:CachedOrganization
            } else {
                $org = Get-MgOrganization
            }
            
            # Try to get the SharePoint tenant name from the .onmicrosoft.com domain
            $onMicrosoftDomain = $org.VerifiedDomains | Where-Object { $_.Name -like "*.onmicrosoft.com" } | Select-Object -First 1
            
            if ($onMicrosoftDomain) {
                $tenantName = $onMicrosoftDomain.Name -replace '\.onmicrosoft\.com$', ''
                $adminUrl = "https://$tenantName-admin.sharepoint.com"
                Write-Host "  [INFO] Detected SharePoint Admin URL: $adminUrl" -ForegroundColor Gray
            } else {
                # Fallback to default domain
                $defaultDomain = ($org.VerifiedDomains | Where-Object {$_.IsDefault}).Name
                $tenantName = $defaultDomain.Split('.')[0]
                $adminUrl = "https://$tenantName-admin.sharepoint.com"
                Write-Host "  [INFO] Guessed SharePoint Admin URL: $adminUrl" -ForegroundColor Yellow
            }
        }

        if ($UseInteractive) {
            Write-Host "  [INFO] Initiating interactive authentication..." -ForegroundColor Cyan
            Write-Host "  [INFO] A browser window will open for you to sign in" -ForegroundColor Gray

            # Get Client ID from environment variable, file, or prompt user
            $pnpClientId = $null
            
            # Check environment variable first
            if ($env:ENTRAID_CLIENT_ID) {
                $pnpClientId = $env:ENTRAID_CLIENT_ID
                Write-Host "  [INFO] Using Client ID from environment variable" -ForegroundColor Gray
            }
            # Check for saved client ID file
            elseif (Test-Path (Join-Path $PSScriptRoot "pnp-client-id.txt")) {
                $pnpClientId = Get-Content (Join-Path $PSScriptRoot "pnp-client-id.txt") -Raw | ForEach-Object { $_.Trim() }
                Write-Host "  [INFO] Using Client ID from saved configuration" -ForegroundColor Gray
            }
            
            # If no Client ID found, provide instructions
            if ([string]::IsNullOrWhiteSpace($pnpClientId)) {
                Write-Host ""
                Write-Host "  [ERROR] No Entra ID App Client ID found!" -ForegroundColor Red
                Write-Host ""
                Write-Host "  As of September 2024, you must register your own Entra ID app." -ForegroundColor Yellow
                Write-Host ""
                Write-Host "  Please run the registration script first:" -ForegroundColor Yellow
                Write-Host "    .\00a-Register-PnP-App.ps1 -TenantDomain 'yourtenant.onmicrosoft.com'" -ForegroundColor Cyan
                Write-Host ""
                throw "Client ID not found. Please register an Entra ID app first."
            }

            # Attempt connection, prompt for URL if it fails
            $connectionAttempts = 0
            $maxConnectionAttempts = 2
            $connected = $false

            while ($connectionAttempts -lt $maxConnectionAttempts -and -not $connected) {
                try {
                    # Use Interactive authentication with PnP Management Shell App ID
                    # This will open a browser window for authentication
                    Connect-PnPOnline -Url $adminUrl -Interactive -ClientId $pnpClientId -ErrorAction Stop
                    $connected = $true
                    Write-Host "  [INFO] Authentication completed, verifying connection..." -ForegroundColor Cyan
                } catch {
                    $connectionAttempts++
                    if ($connectionAttempts -lt $maxConnectionAttempts) {
                        Write-Host "  [WARN] Failed to connect to $adminUrl" -ForegroundColor Yellow
                        Write-Host "  [WARN] Error: $_" -ForegroundColor Yellow
                        Write-Host ""

                        # Prompt for correct URL
                        Write-Host "  The auto-detected URL may be incorrect." -ForegroundColor Yellow
                        Write-Host "  Please enter your SharePoint Admin URL:" -ForegroundColor Cyan
                        Write-Host "  (Example: https://yourtenant-admin.sharepoint.com)" -ForegroundColor Gray
                        Write-Host "  (Or press Enter to retry the same URL)" -ForegroundColor Gray
                        $userInput = Read-Host "  SharePoint Admin URL"

                        if (-not [string]::IsNullOrWhiteSpace($userInput)) {
                            $adminUrl = $userInput
                        }
                        
                        Write-Host "  [INFO] Retrying connection..." -ForegroundColor Cyan
                    } else {
                        throw $_
                    }
                }
            }
        } else {
            Connect-PnPOnline -Url $adminUrl -ClientId $ApplicationId -Tenant $TenantId -Thumbprint $CertificateThumbprint -ErrorAction Stop
        }

        # Verify connection with a simple test command
        $maxRetries = 3
        $retryCount = 0
        $verified = $false

        while ($retryCount -lt $maxRetries -and -not $verified) {
            try {
                # Try to get the web - this will fail if not actually connected
                $web = Get-PnPWeb -ErrorAction Stop
                if ($web) {
                    $verified = $true
                    break
                }
            } catch {
                Write-Host "  [RETRY] Connection verification failed (attempt $($retryCount + 1)/$maxRetries)..." -ForegroundColor Yellow
                Write-Host "    Error: $_" -ForegroundColor Gray
                Start-Sleep -Seconds 2
            }
            $retryCount++
        }

        if (-not $verified) {
            throw "Failed to verify SharePoint Online connection after $maxRetries attempts"
        }

        $connection = Get-PnPConnection
        Write-Host "  [OK] Connected to SharePoint Online" -ForegroundColor Green
        Write-Host "    URL: $($connection.Url)" -ForegroundColor Gray

        return $true
    } catch {
        Write-Error "Failed to connect to SharePoint Online: $_"
        return $false
    }
}

# Function to connect to Microsoft Teams
function Connect-ToMicrosoftTeams {
    Write-Host "`n[4/4] Connecting to Microsoft Teams..." -ForegroundColor Yellow

    try {
        # Check for existing connection by trying to get account info
        try {
            $existingConnection = Get-CsTeamsCallingPolicy -ErrorAction SilentlyContinue
            if ($existingConnection -or $?) {
                # Try to get tenant info as secondary check
                $existingTenant = Get-CsTenant -ErrorAction SilentlyContinue
                if ($existingTenant) {
                    Write-Host "  [INFO] Already connected to Microsoft Teams" -ForegroundColor Cyan
                    Write-Host "    Tenant: $($existingTenant.DisplayName)" -ForegroundColor Gray
                    return $true
                }
            }
        } catch {
            # Not connected, proceed with connection
        }

        Write-Host "  [INFO] Establishing Teams connection..." -ForegroundColor Cyan
        
        if ($UseInteractive) {
            $result = Connect-MicrosoftTeams -ErrorAction Stop
            if ($result) {
                Write-Host "  [INFO] Connection established" -ForegroundColor Gray
            }
        } else {
            $result = Connect-MicrosoftTeams -ApplicationId $ApplicationId -TenantId $TenantId -CertificateThumbprint $CertificateThumbprint -ErrorAction Stop
            if ($result) {
                Write-Host "  [INFO] Connection established" -ForegroundColor Gray
            }
        }

        # Verify connection with retry
        $maxRetries = 3
        $retryCount = 0
        $context = $null

        while ($retryCount -lt $maxRetries -and $null -eq $context) {
            try {
                Start-Sleep -Seconds 1
                $context = Get-CsTenant -ErrorAction Stop
                if ($context) {
                    break
                }
            } catch {
                if ($retryCount -lt $maxRetries - 1) {
                    Write-Host "  [RETRY] Attempting to verify connection (attempt $($retryCount + 1)/$maxRetries)..." -ForegroundColor Yellow
                    Start-Sleep -Seconds 2
                }
            }
            $retryCount++
        }

        if ($null -eq $context) {
            Write-Warning "Could not verify Microsoft Teams connection, but connection may still be established."
            Write-Host "  [INFO] Proceeding without verification..." -ForegroundColor Yellow
            return $true
        }

        Write-Host "  [OK] Connected to Microsoft Teams" -ForegroundColor Green
        Write-Host "    Tenant: $($context.DisplayName)" -ForegroundColor Gray

        return $true
    } catch {
        Write-Error "Failed to connect to Microsoft Teams: $_"
        return $false
    }
}

# Main execution
try {
    # Check PowerShell environment
    Test-PowerShellEnvironment

    # Check and install required modules
    if (-not (Install-RequiredModules)) {
        throw "Module installation failed or was cancelled."
    }

    Write-Host "`n" + ("="*60) -ForegroundColor Cyan
    Write-Host "Starting connection to Microsoft 365 services..." -ForegroundColor Cyan
    Write-Host ("="*60) -ForegroundColor Cyan

    # Connect to each service
    $graphConnected = Connect-ToMicrosoftGraph

    # Cache organization info after Graph connects (to avoid module conflicts later)
    $script:CachedOrganization = $null
    if ($graphConnected) {
        try {
            $script:CachedOrganization = Get-MgOrganization -ErrorAction Stop
            Write-Host "`n[INFO] Organization info cached successfully" -ForegroundColor Gray
        } catch {
            Write-Warning "Failed to cache organization info: $_"
        }
    }

    $exchangeConnected = Connect-ToExchangeOnline
    $sharepointConnected = Connect-ToSharePointOnline
    $teamsConnected = Connect-ToMicrosoftTeams

    # Summary
    Write-Host "`n" + ("="*60) -ForegroundColor Cyan
    Write-Host "Connection Summary:" -ForegroundColor Cyan
    Write-Host ("="*60) -ForegroundColor Cyan

    Write-Host "Microsoft Graph:     $(if($graphConnected){'[OK] Connected'}else{'[FAIL]'})" -ForegroundColor $(if($graphConnected){'Green'}else{'Red'})
    Write-Host "Exchange Online:     $(if($exchangeConnected){'[OK] Connected'}else{'[FAIL]'})" -ForegroundColor $(if($exchangeConnected){'Green'}else{'Red'})
    Write-Host "SharePoint Online:   $(if($sharepointConnected){'[OK] Connected'}else{'[FAIL]'})" -ForegroundColor $(if($sharepointConnected){'Green'}else{'Red'})
    Write-Host "Microsoft Teams:     $(if($teamsConnected){'[OK] Connected'}else{'[FAIL]'})" -ForegroundColor $(if($teamsConnected){'Green'}else{'Red'})

    if ($graphConnected -and $exchangeConnected -and $sharepointConnected -and $teamsConnected) {
        Write-Host "`n[OK] All services connected successfully! Ready to run audit scripts." -ForegroundColor Green
    } else {
        Write-Warning "`nSome services failed to connect. Review errors above."
        Write-Host "`n[TROUBLESHOOTING]" -ForegroundColor Yellow
        Write-Host "If you encountered connection errors:" -ForegroundColor Yellow
        Write-Host "1. Ensure you have the necessary permissions for Microsoft 365 services" -ForegroundColor Gray
        Write-Host "2. Check your internet connection" -ForegroundColor Gray
        Write-Host "3. Try running the script in a new PowerShell session" -ForegroundColor Gray
        Write-Host "4. For interactive auth, ensure you're running in an interactive PowerShell window" -ForegroundColor Gray
        exit 1
    }
} catch {
    Write-Host "`n[ERROR] Script execution failed: $_" -ForegroundColor Red
    Write-Host "`n[TROUBLESHOOTING]" -ForegroundColor Yellow
    Write-Host "Common solutions:" -ForegroundColor Yellow
    Write-Host "1. Run PowerShell as Administrator" -ForegroundColor Gray
    Write-Host "2. Check your Microsoft 365 credentials and permissions" -ForegroundColor Gray
    Write-Host "3. Ensure all required modules are installed correctly" -ForegroundColor Gray
    Write-Host "4. Try: Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser" -ForegroundColor Gray
    exit 1
}

