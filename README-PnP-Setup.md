# PnP PowerShell Setup

## Important Change (September 2024)

As of September 9, 2024, the default PnP Management Shell Entra ID application was deprecated. You must now register your own Entra ID application to use PnP PowerShell for interactive authentication.

## First-Time Setup

### Step 1: Register Your Entra ID Application

Run the registration script **once** to create your custom app:

```powershell
.\00a-Register-PnP-App.ps1 -TenantDomain "yourcompany.onmicrosoft.com"
```

**Requirements:**
- You must be a **Global Administrator** or **Application Administrator**
- A browser window will open for authentication
- The script will create an app named "M365 Audit - PnP PowerShell"

**What it does:**
- Registers a new Entra ID application in your tenant
- Configures required SharePoint and Microsoft Graph permissions
- Saves the Client ID to `pnp-client-id.txt` for future use

### Step 2: Connect to Microsoft 365

After registration, run the connection script as normal:

```powershell
.\00-Connect-M365.ps1
```

The script will automatically use your registered Client ID from the saved file.

## Optional: Use Environment Variable

Instead of saving the Client ID to a file, you can set it as an environment variable:

```powershell
.\00a-Register-PnP-App.ps1 -TenantDomain "yourcompany.onmicrosoft.com" -SetEnvironmentVariable
```

This sets the `ENTRAID_CLIENT_ID` environment variable for your user account.

**Note:** You'll need to restart PowerShell after setting the environment variable.

## Troubleshooting

### Error: "Application with identifier '31359c7f-bd7e-475c-86db-fdb8c937548e' was not found"

This means you're using the old deprecated Client ID. Run the registration script (Step 1) to create your own app.

### Error: "Client ID not found"

The connection script couldn't find your Client ID. Options:

1. Run the registration script: `.\00a-Register-PnP-App.ps1`
2. Check if `pnp-client-id.txt` exists in the Scripts folder
3. Set the environment variable: `$env:ENTRAID_CLIENT_ID = "your-client-id"`

### Error during registration: "Insufficient privileges"

You need Global Administrator or Application Administrator rights to register Entra ID applications. Contact your tenant administrator.

## How It Works

The connection script looks for the Client ID in this order:

1. **Environment Variable** (`ENTRAID_CLIENT_ID`)
2. **Configuration File** (`pnp-client-id.txt`)
3. If neither found, displays an error with setup instructions

## Files

- `00a-Register-PnP-App.ps1` - One-time registration script
- `00-Connect-M365.ps1` - Main connection script (updated to use custom app)
- `pnp-client-id.txt` - Saved Client ID (created by registration script)
- `README-PnP-Setup.md` - This file

## Permissions Granted

The registered app has the following delegate permissions:

**SharePoint:**
- AllSites.FullControl
- TermStore.ReadWrite.All
- User.ReadWrite.All

**Microsoft Graph:**
- Group.ReadWrite.All
- User.ReadWrite.All
- Directory.ReadWrite.All

These permissions are appropriate for IT audit and administration tasks.

## Security Notes

- The Client ID is not a secret and can be safely stored in version control
- Each authentication requires user login (interactive flow)
- Admin consent may be required for some permissions
- The app is registered only in your tenant (not multi-tenant)

