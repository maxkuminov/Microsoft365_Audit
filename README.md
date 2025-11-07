---
date: 2025-11-05
type: documentation
tags:
  - documentation
  - m365
  - audit
---

# Microsoft 365 IT Audit Framework

This folder contains a comprehensive Microsoft 365 audit framework for documenting and analyzing your organization's M365 environment.

## 📁 Folder Structure

```
IT/
├── M365 Audit Plan.md          # Comprehensive audit planning document
├── README.md                    # This file - quick start guide
├── Scripts/                     # PowerShell audit scripts
│   ├── 00-Connect-M365.ps1     # Connection manager (START HERE)
│   ├── 01-Export-Users.ps1     # Export user accounts and licenses
│   ├── 02-Export-SharePoint.ps1    # Export SharePoint sites
│   ├── 03-Export-SharedMailboxes.ps1   # Export shared mailboxes
│   ├── 04-Export-Groups.ps1    # Export all group types
│   └── [Additional scripts as needed]
├── Data/                        # Raw data exports (CSV/JSON)
│   └── [Timestamped folders with exports]
└── Reports/                     # Generated reports and summaries
    └── [Analysis and findings]
```

## 🚀 Quick Start

### Prerequisites
- PowerShell 7.x or later (recommended)
- Windows PowerShell 5.1 (minimum)
- Administrator access to Microsoft 365 tenant
- Appropriate permissions (Global Reader role minimum)

### Step 1: First Time Setup

1. **Open PowerShell as Administrator**

2. **Run the connection script** (it will automatically check and install required modules):
   ```powershell
   cd "C:\Scripts\Microsoft365_Audit"
   .\00-Connect-M365.ps1
   ```

3. **Sign in** when prompted with your M365 admin account

4. **Grant consent** to the requested permissions when prompted

### Step 2: Run Individual Audit Scripts

Once connected, run audit scripts in sequence:

```powershell
# Export users and licensing
.\01-Export-Users.ps1

# Export SharePoint sites
.\02-Export-SharePoint.ps1

# Export shared mailboxes
.\03-Export-SharedMailboxes.ps1

# Export groups
.\04-Export-Groups.ps1

# ... and so on
```

### Step 3: Review Data

- Exported data will be saved to `Data/` folder with timestamps
- Review CSV files in Excel or import into analysis tools
- Check `Reports/` folder for generated summaries

## 📦 Required PowerShell Modules

The audit framework requires these modules (auto-installed by connection script):

1. **Microsoft.Graph** - For Azure AD, users, groups, sites
2. **ExchangeOnlineManagement** - For Exchange, mailboxes, mail flow
3. **PnP.PowerShell** - For detailed SharePoint operations
4. **MicrosoftTeams** - For Teams configuration and membership

### Manual Installation (if needed)

```powershell
# Install all modules at once
Install-Module Microsoft.Graph, ExchangeOnlineManagement, PnP.PowerShell, MicrosoftTeams -Scope CurrentUser -Force
```

## 🔐 Authentication Options

### Option 1: Interactive (Default)
Best for manual audits. Uses browser-based authentication with MFA support.

```powershell
.\00-Connect-M365.ps1
```

### Option 2: Certificate-Based (For Automation)
Best for scheduled/automated audits. Requires app registration setup.

```powershell
.\00-Connect-M365.ps1 `
    -UseInteractive:$false `
    -ApplicationId "your-app-id" `
    -CertificateThumbprint "your-cert-thumbprint" `
    -TenantId "your-tenant-id"
```

#### Setting Up Certificate Authentication

1. **Create App Registration** in Azure Portal
2. **Configure API Permissions** (see M365 Audit Plan.md for full list)
3. **Upload certificate** or create self-signed cert
4. **Grant admin consent** for permissions
5. **Use credentials** in script parameters

**Quick self-signed cert creation:**
```powershell
$cert = New-SelfSignedCertificate -Subject "CN=M365Audit" `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -KeyExportPolicy Exportable `
    -KeySpec Signature `
    -KeyLength 2048 `
    -KeyAlgorithm RSA `
    -HashAlgorithm SHA256 `
    -NotAfter (Get-Date).AddYears(2)

# Export certificate for upload to Azure
Export-Certificate -Cert $cert -FilePath "M365Audit.cer"

# Note the thumbprint
$cert.Thumbprint
```

## 📊 What Gets Audited

### Core Items
- ✅ **Users** - Accounts, licenses, MFA status, sign-in activity
- ✅ **SharePoint Sites** - Site collections, storage, permissions, sharing
- ✅ **Shared Mailboxes** - Mailbox details, permissions, usage
- ✅ **Groups** - M365 Groups, Distribution Lists, Security Groups

### Extended Items (Plan for future scripts)
- Teams and channels
- OneDrive storage and sharing
- Exchange mail flow rules
- Conditional access policies
- Security and compliance settings
- Application registrations
- External users and guests

## 🛡️ Security & Compliance

### Data Handling
- Audit data contains **sensitive information** (emails, names, licenses)
- Store data securely and encrypt if needed
- Follow data retention policies
- Limit access to audit results

### Recommended Practices
1. Run audits from secure workstation
2. Use certificate authentication for automation
3. Review and remove old audit data regularly
4. Document who ran audits and when
5. Never commit sensitive data to version control

## 📅 Recommended Audit Schedule

- **Monthly**: Quick review of users and licenses
- **Quarterly**: Full audit of all components
- **Annually**: Comprehensive security and compliance review
- **Ad-hoc**: Before/after major changes or incidents

## 🔧 Troubleshooting

### "Module not found" errors
```powershell
# Force reinstall of module
Install-Module ModuleName -Force -Scope CurrentUser
```

### "Insufficient permissions" errors
- Verify you have Global Reader or appropriate admin role
- Check that app registration has correct API permissions
- Ensure admin consent has been granted

### Connection timeouts
```powershell
# Disconnect and reconnect
Disconnect-MgGraph
Disconnect-ExchangeOnline -Confirm:$false
.\00-Connect-M365.ps1
```

### "Certificate not found" errors
- Verify certificate is in correct store (CurrentUser\My)
- Check certificate hasn't expired
- Ensure thumbprint matches exactly

## 📚 Additional Resources

- [M365 Audit Plan.md](./M365%20Audit%20Plan.md) - Detailed planning document
- [Microsoft Graph PowerShell SDK Docs](https://learn.microsoft.com/en-us/powershell/microsoftgraph/)
- [Exchange Online PowerShell Docs](https://learn.microsoft.com/en-us/powershell/exchange/exchange-online-powershell)
- [PnP PowerShell Docs](https://pnp.github.io/powershell/)

## 🤝 Contributing

When adding new audit scripts:
1. Follow naming convention: `##-Export-Component.ps1`
2. Include help comments and examples
3. Export data with timestamps
4. Handle errors gracefully
5. Add summary to this README

## 📝 Notes

- Scripts are designed to be read-only (no modifications to M365)
- All connections use least-privilege principle
- Data exports include timestamps for version control
- Consider using version control (Git) for scripts only (not data)

---

**Last Updated**: 2025-11-05
**Maintained By**: Max (via Cursor AI)

