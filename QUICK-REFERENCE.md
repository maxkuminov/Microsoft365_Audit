# Microsoft 365 Audit - Quick Reference Card

## 🚀 Quick Start (3 Steps)

### 1. Open PowerShell
```powershell
cd "scripts_folder"
```
One time only - Run 00a-Register-PnP-App.ps1 to register the management app in the Microsoft365 tenant

### 2. Connect to M365
```powershell
.\00-Connect-M365.ps1
```
- Sign in with admin account when prompted
- Grant consent to permissions

### 3. Run Audit Scripts
```powershell
# Users and licenses
.\01-Export-Users.ps1

# SharePoint sites
.\02-Export-SharePoint.ps1

# Shared mailboxes
.\03-Export-SharedMailboxes.ps1

# All groups
.\04-Export-Groups.ps1
```

---

## 🛠️ Troubleshooting

| Problem | Solution |
|---------|----------|
| "Module not found" | Run: `Install-Module ModuleName -Scope CurrentUser -Force` |
| "Not connected" | Run: `.\00-Connect-M365.ps1` |
| "Insufficient permissions" | Verify you have Global Reader or admin role |
| Connection timeout | Disconnect and reconnect |
| Certificate errors | Check cert in CurrentUser\My store |

---

## 🎯 Common Use Cases

### Monthly License Review
```powershell
.\00-Connect-M365.ps1
.\01-Export-Users.ps1
# Review: Data\[timestamp]\Licenses.csv
```

### Quarterly Security Audit
```powershell
.\00-Connect-M365.ps1
.\01-Export-Users.ps1  # Check MFA status
.\03-Export-SharedMailboxes.ps1  # Review permissions
.\04-Export-Groups.ps1  # Check group ownership
```

### Storage Capacity Planning
```powershell
.\00-Connect-M365.ps1
.\02-Export-SharePoint.ps1
# Review: Data\[timestamp]\SharePointSites.csv
```

### Permission Audit
```powershell
.\00-Connect-M365.ps1
.\03-Export-SharedMailboxes.ps1
.\04-Export-Groups.ps1
# Review all permission CSV files
```

**Last Updated**: 2025-11-05

