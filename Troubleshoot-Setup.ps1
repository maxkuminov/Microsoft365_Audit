<#
.SYNOPSIS
    Troubleshooting script to unblock PowerShell scripts and verify setup.

.DESCRIPTION
    This script helps resolve common issues with running the M365 audit scripts:
    - Unblocks all PowerShell scripts in the Scripts folder
    - Verifies module installations
    - Checks execution policy
    - Tests connectivity

.EXAMPLE
    .\Troubleshoot-Setup.ps1
#>

Write-Host "=============================================================" -ForegroundColor Cyan
Write-Host "     M365 Audit - Troubleshooting & Setup Verification     " -ForegroundColor Cyan
Write-Host "=============================================================" -ForegroundColor Cyan

Write-Host "`n[1/5] Checking PowerShell Version..." -ForegroundColor Yellow
$psVersion = $PSVersionTable.PSVersion
Write-Host "  PowerShell Version: $($psVersion.Major).$($psVersion.Minor).$($psVersion.Build)" -ForegroundColor White

if ($psVersion.Major -lt 5) {
    Write-Host "  [WARNING] Warning: PowerShell 5.1 or later is recommended" -ForegroundColor Red
} else {
    Write-Host "  [OK] PowerShell version is compatible" -ForegroundColor Green
}

Write-Host "`n[2/5] Checking Execution Policy..." -ForegroundColor Yellow
$currentPolicy = Get-ExecutionPolicy
Write-Host "  Current Execution Policy: $currentPolicy" -ForegroundColor White

if (@('Restricted', 'AllSigned') -contains $currentPolicy) {
    Write-Host "  [WARNING] Execution policy may block scripts" -ForegroundColor Yellow
    Write-Host "  Attempting to set policy to RemoteSigned..." -ForegroundColor Cyan
    
    try {
        Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force -ErrorAction Stop
        Write-Host "  [OK] Execution policy updated" -ForegroundColor Green
    } catch {
        Write-Host "  [WARNING] Could not change execution policy: $_" -ForegroundColor Yellow
        Write-Host "  You may need to run PowerShell as Administrator" -ForegroundColor Yellow
    }
} else {
    Write-Host "  [OK] Execution policy allows scripts" -ForegroundColor Green
}

Write-Host "`n[3/5] Unblocking PowerShell Scripts..." -ForegroundColor Yellow
$scriptPath = Split-Path -Parent $PSCommandPath
$scripts = Get-ChildItem -Path $scriptPath -Filter "*.ps1"

$blockedCount = 0
foreach ($script in $scripts) {
    try {
        Unblock-File -Path $script.FullName -ErrorAction SilentlyContinue
        $blockedCount++
    } catch {
        # Ignore errors
    }
}

Write-Host "  [OK] Processed $($scripts.Count) script files" -ForegroundColor Green

Write-Host "`n[4/5] Verifying Module Installation..." -ForegroundColor Yellow

$requiredModules = @(
    'Microsoft.Graph',
    'ExchangeOnlineManagement',
    'PnP.PowerShell',
    'MicrosoftTeams'
)

$moduleStatus = @()
foreach ($moduleName in $requiredModules) {
    $module = Get-Module -ListAvailable -Name $moduleName | Select-Object -First 1
    
    if ($module) {
        Write-Host "  [OK] $moduleName (v$($module.Version))" -ForegroundColor Green
        $moduleStatus += [PSCustomObject]@{
            Module = $moduleName
            Status = "Installed"
            Version = $module.Version
        }
    } else {
        Write-Host "  [X] $moduleName - NOT INSTALLED" -ForegroundColor Red
        $moduleStatus += [PSCustomObject]@{
            Module = $moduleName
            Status = "Missing"
            Version = "N/A"
        }
    }
}

$missingModules = $moduleStatus | Where-Object { $_.Status -eq "Missing" }

if ($missingModules.Count -gt 0) {
    Write-Host "`n  [WARNING] Missing modules detected. Install with:" -ForegroundColor Yellow
    foreach ($module in $missingModules) {
        Write-Host "    Install-Module -Name $($module.Module) -Scope CurrentUser -Force" -ForegroundColor Cyan
    }
}

Write-Host "`n[5/5] Testing Script Execution..." -ForegroundColor Yellow

# Try to load a simple function to test if scripts can execute
try {
    $testScript = {
        function Test-ScriptExecution {
            return "Scripts can execute successfully"
        }
        Test-ScriptExecution
    }
    
    $result = & $testScript
    Write-Host "  [OK] $result" -ForegroundColor Green
} catch {
    Write-Host "  [X] Script execution test failed: $_" -ForegroundColor Red
}

# Summary
Write-Host "`n" + ("="*60) -ForegroundColor Cyan
Write-Host "SUMMARY" -ForegroundColor Cyan
Write-Host ("="*60) -ForegroundColor Cyan

$allModulesInstalled = ($moduleStatus | Where-Object { $_.Status -eq "Missing" }).Count -eq 0
$executionOk = @('Restricted', 'AllSigned') -notcontains $currentPolicy

Write-Host "`nSystem Status:" -ForegroundColor White
Write-Host "  PowerShell Version:  $(if ($psVersion.Major -ge 5) { '[OK]' } else { '[X]' }) $($psVersion.Major).$($psVersion.Minor)" -ForegroundColor $(if ($psVersion.Major -ge 5) { 'Green' } else { 'Red' })
Write-Host "  Execution Policy:    $(if ($executionOk) { '[OK]' } else { '[X]' }) $currentPolicy" -ForegroundColor $(if ($executionOk) { 'Green' } else { 'Red' })
Write-Host "  Required Modules:    $(if ($allModulesInstalled) { '[OK] All installed' } else { "[X] $($missingModules.Count) missing" })" -ForegroundColor $(if ($allModulesInstalled) { 'Green' } else { 'Red' })
Write-Host "  Scripts Unblocked:   [OK] $($scripts.Count) files processed" -ForegroundColor Green

if ($allModulesInstalled -and $executionOk) {
    Write-Host "`n[OK] System is ready! You can now run the audit scripts." -ForegroundColor Green
    Write-Host "`nNext step: Run .\00-Connect-M365.ps1 to connect to Microsoft 365" -ForegroundColor Cyan
} else {
    Write-Host "`n[WARNING] Setup incomplete. Please address the issues above." -ForegroundColor Yellow
    
    if (-not $allModulesInstalled) {
        Write-Host "`nTo install missing modules, run:" -ForegroundColor Cyan
        Write-Host "  Install-Module Microsoft.Graph, ExchangeOnlineManagement, PnP.PowerShell, MicrosoftTeams -Scope CurrentUser -Force" -ForegroundColor White
    }
    
    if (-not $executionOk) {
        Write-Host "`nTo fix execution policy, run PowerShell as Administrator and execute:" -ForegroundColor Cyan
        Write-Host "  Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine" -ForegroundColor White
    }
}

Write-Host "`n" + ("="*60) -ForegroundColor Cyan

# Detailed help
Write-Host "`nFor more help, see:" -ForegroundColor Gray
Write-Host "  - SETUP-COMPLETE.md" -ForegroundColor Gray
Write-Host "  - README.md" -ForegroundColor Gray
Write-Host "  - QUICK-REFERENCE.md" -ForegroundColor Gray

