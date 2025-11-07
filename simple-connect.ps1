# Simple connection test
Write-Host "Testing Microsoft Graph connection..." -ForegroundColor Cyan

try {
    # Check if module exists
    $module = Get-Module -ListAvailable -Name Microsoft.Graph
    if ($null -eq $module) {
        Write-Host "Microsoft.Graph module not found. Installing..." -ForegroundColor Yellow
        Install-Module -Name Microsoft.Graph -Scope CurrentUser -Force
    }

    Write-Host "Module available. Attempting connection..." -ForegroundColor Green

    # This will require interactive authentication
    Connect-MgGraph -Scopes "User.Read.All" -NoWelcome

    Write-Host "Connection successful!" -ForegroundColor Green
} catch {
    Write-Error "Connection failed: $_"
}
