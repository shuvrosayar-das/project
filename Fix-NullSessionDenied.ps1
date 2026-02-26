#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Fix-NullSessionDenied.ps1
    Resolves NT_STATUS_ACCESS_DENIED on anonymous SMB null session connections.
    Run on the Windows Server 2016 target VM from an elevated PowerShell prompt.

    Usage:
        powershell.exe -ExecutionPolicy Bypass -File .\Fix-NullSessionDenied.ps1
#>

# ==============================================================================
# HELPERS
# ==============================================================================
function Write-Log {
    param([string]$Msg, [string]$Level = "INFO")
    $ts = Get-Date -Format "HH:mm:ss"
    $color = switch ($Level) {
        "SUCCESS" { "Green"  }
        "WARN"    { "Yellow" }
        "ERROR"   { "Red"    }
        default   { "Cyan"   }
    }
    Write-Host ("[$ts][$Level] " + $Msg) -ForegroundColor $color
}

function Set-RegDWord {
    param([string]$Path, [string]$Name, [int]$Value)
    try {
        if (-not (Test-Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
        }
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -Force
        $verify = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name
        if ($verify -eq $Value) {
            Write-Log ("SET OK: " + $Name + " = " + $Value + " at " + $Path) "SUCCESS"
        } else {
            Write-Log ("MISMATCH: " + $Name + " = " + $verify + " (wanted " + $Value + ")") "ERROR"
        }
    } catch {
        Write-Log ("FAILED: " + $Name + " -> " + $_.Exception.Message) "ERROR"
    }
}

function Set-RegMultiString {
    param([string]$Path, [string]$Name, [string[]]$Values)
    try {
        if (-not (Test-Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
        }
        Set-ItemProperty -Path $Path -Name $Name -Value $Values -Type MultiString -Force
        Write-Log ("SET OK: " + $Name + " = [" + ($Values -join ", ") + "]") "SUCCESS"
    } catch {
        Write-Log ("FAILED: " + $Name + " -> " + $_.Exception.Message) "ERROR"
    }
}

# ==============================================================================
# BANNER
# ==============================================================================
Clear-Host
Write-Host ""
Write-Host "+-------------------------------------------------------------+" -ForegroundColor Red
Write-Host "|  Fix-NullSessionDenied.ps1                                  |" -ForegroundColor Red
Write-Host "|  Resolves NT_STATUS_ACCESS_DENIED on anonymous SMB sessions |" -ForegroundColor Red
Write-Host "+-------------------------------------------------------------+" -ForegroundColor Red
Write-Host ""

# ==============================================================================
# SECTION 1 -- REGISTRY: LSA NULL SESSION KEYS
# The most common cause. These control whether anonymous RPC/SMB is allowed.
# ==============================================================================
Write-Log "--- SECTION 1: LSA null session registry keys ---"

$LSA = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"

# 0 = allow anonymous enumeration of SAM accounts and shares
Set-RegDWord -Path $LSA -Name "RestrictAnonymous"    -Value 0

# 0 = allow anonymous enumeration of SAM accounts
Set-RegDWord -Path $LSA -Name "RestrictAnonymousSAM" -Value 0

# 1 = allow anonymous connections to list account names and enumerate shares
# (everyoneincludesanonymous is needed so "Everyone" ACE applies to null sessions)
Set-RegDWord -Path $LSA -Name "EveryoneIncludesAnonymous" -Value 1

# ==============================================================================
# SECTION 2 -- REGISTRY: LANMAN SERVER NULL SESSION PIPES AND SHARES
# Without NullSessionPipes, rpcclient/enum4linux cannot open named pipes anonymously.
# Without NullSessionShares, IPC$ is not accessible anonymously.
# ==============================================================================
Write-Log "--- SECTION 2: LanmanServer null session pipes and shares ---"

$LanMan = "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"

# Named pipes accessible without authentication
Set-RegMultiString -Path $LanMan -Name "NullSessionPipes" `
    -Values @("samr", "lsarpc", "netlogon", "srvsvc", "wkssvc", "browser")

# Shares accessible without authentication
Set-RegMultiString -Path $LanMan -Name "NullSessionShares" `
    -Values @("IPC`$", "BackupShare")

# ==============================================================================
# SECTION 3 -- REGISTRY: LOCAL ACCOUNT TOKEN FILTER POLICY
# Required for PSExec with local admin accounts to get a non-filtered token.
# ==============================================================================
Write-Log "--- SECTION 3: LocalAccountTokenFilterPolicy ---"

$Policies = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
Set-RegDWord -Path $Policies -Name "LocalAccountTokenFilterPolicy" -Value 1

# ==============================================================================
# SECTION 4 -- FIX SMB SHARE PERMISSIONS
# Both the share-level ACL and NTFS ACL must grant Everyone access.
# A common failure point: share says Everyone:Full but NTFS still blocks anonymous.
# ==============================================================================
Write-Log "--- SECTION 4: Share and NTFS permissions ---"

$ShareName = "BackupShare"
$SharePath = "C:\BackupShare"

# Ensure share directory exists
if (-not (Test-Path $SharePath)) {
    New-Item -ItemType Directory -Path $SharePath -Force | Out-Null
    Write-Log ("Created share directory: " + $SharePath) "SUCCESS"
}

# Remove and recreate the share cleanly
$existing = Get-SmbShare -Name $ShareName -ErrorAction SilentlyContinue
if ($null -ne $existing) {
    Remove-SmbShare -Name $ShareName -Force
    Write-Log ("Removed existing share: " + $ShareName) "WARN"
}

New-SmbShare -Name $ShareName `
    -Path $SharePath `
    -Description "Backup Configuration Files" `
    -FullAccess "Everyone" `
    -ErrorAction Stop | Out-Null
Write-Log ("Share created: \\" + $env:COMPUTERNAME + "\" + $ShareName + " (Everyone:FullAccess)") "SUCCESS"

# Fix NTFS ACL -- Everyone must have FullControl at the filesystem level too
# First remove inherited restrictions, then add explicit Everyone:Full
try {
    $acl = Get-Acl -Path $SharePath

    # Enable inheritance and remove protect
    $acl.SetAccessRuleProtection($false, $true)

    # Add explicit Everyone:FullControl
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        "Everyone",
        "FullControl",
        "ContainerInherit,ObjectInherit",
        "None",
        "Allow"
    )
    $acl.AddAccessRule($rule)
    Set-Acl -Path $SharePath -AclObject $acl
    Write-Log "NTFS ACL: Everyone:FullControl applied" "SUCCESS"
} catch {
    Write-Log ("NTFS ACL failed: " + $_.Exception.Message) "ERROR"
    Write-Log "Falling back to icacls..." "WARN"
    # Fallback: use icacls directly
    & icacls $SharePath /grant "Everyone:(OI)(CI)(F)" /T /C 2>&1 | ForEach-Object { Write-Log $_ }
}

# Verify share-level ACL
try {
    $shareAccess = Get-SmbShareAccess -Name $ShareName
    foreach ($entry in $shareAccess) {
        Write-Log ("Share ACL: " + $entry.AccountName + " = " + $entry.AccessRight) "SUCCESS"
    }
} catch {
    Write-Log ("Could not verify share ACL: " + $_.Exception.Message) "WARN"
}

# ==============================================================================
# SECTION 5 -- SMB SERVER CONFIGURATION
# Disable signing requirement and encryption. Both block null sessions.
# ==============================================================================
Write-Log "--- SECTION 5: SMB server configuration ---"

try {
    Set-SmbServerConfiguration -EnableSMB1Protocol        $true  -Force -ErrorAction SilentlyContinue
    Set-SmbServerConfiguration -EnableSMB2Protocol        $true  -Force -ErrorAction SilentlyContinue
    Set-SmbServerConfiguration -RequireSecuritySignature  $false -Force
    Set-SmbServerConfiguration -EnableSecuritySignature   $true  -Force
    Set-SmbServerConfiguration -EncryptData               $false -Force
    Set-SmbServerConfiguration -RejectUnencryptedAccess   $false -Force -ErrorAction SilentlyContinue
    Write-Log "SMB: signing not required, encryption off, SMB1+2 enabled" "SUCCESS"
} catch {
    Write-Log ("SMB config error: " + $_.Exception.Message) "WARN"
}

# ==============================================================================
# SECTION 6 -- DISABLE WINDOWS DEFENDER
# Defender can block anonymous SMB sessions at the network driver level.
# ==============================================================================
Write-Log "--- SECTION 6: Windows Defender ---"

try {
    Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
    Set-MpPreference -DisableIOAVProtection     $true -ErrorAction SilentlyContinue
    Set-MpPreference -DisableScriptScanning     $true -ErrorAction SilentlyContinue
    Write-Log "Defender real-time monitoring disabled" "SUCCESS"
} catch {
    Write-Log "Defender already off or not present" "WARN"
}

# ==============================================================================
# SECTION 7 -- FIREWALL: OPEN ALL REQUIRED PORTS
# UDP 137/138 for NetBIOS, TCP 139 for NetBIOS session, TCP 445 for SMB direct.
# If any of these are blocked, smbclient gets different error messages.
# ==============================================================================
Write-Log "--- SECTION 7: Windows Firewall ---"

# Nuclear option for lab -- fully disable firewall
try {
    & netsh advfirewall set allprofiles state off 2>&1 | Out-Null
    Write-Log "Windows Firewall DISABLED (all profiles)" "SUCCESS"
} catch {
    Write-Log "Could not disable firewall via netsh, trying PowerShell..." "WARN"
    try {
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
        Write-Log "Windows Firewall disabled via Set-NetFirewallProfile" "SUCCESS"
    } catch {
        Write-Log ("Firewall disable failed: " + $_.Exception.Message) "ERROR"
    }
}

# Also explicitly open the ports as a belt-and-suspenders measure
$ports = @(
    @{ Name = "Lab-TCP-445";     Port = 445; Proto = "TCP" },
    @{ Name = "Lab-TCP-139";     Port = 139; Proto = "TCP" },
    @{ Name = "Lab-TCP-135";     Port = 135; Proto = "TCP" },
    @{ Name = "Lab-UDP-137";     Port = 137; Proto = "UDP" },
    @{ Name = "Lab-UDP-138";     Port = 138; Proto = "UDP" }
)
foreach ($p in $ports) {
    $ex = Get-NetFirewallRule -DisplayName $p.Name -ErrorAction SilentlyContinue
    if ($null -eq $ex) {
        New-NetFirewallRule -DisplayName $p.Name -Direction Inbound `
            -Protocol $p.Proto -LocalPort $p.Port -Action Allow -Profile Any | Out-Null
        Write-Log ("Firewall rule added: " + $p.Name) "SUCCESS"
    }
}

# ==============================================================================
# SECTION 8 -- RESTART THE SERVER SERVICE
# This is the step most people miss. Registry changes to LanmanServer and LSA
# do NOT take effect until the Server service is restarted. A reboot also works
# but is not required if you restart the service.
# ==============================================================================
Write-Log "--- SECTION 8: Restarting Server service to apply registry changes ---"

try {
    Write-Log "Stopping Server (LanmanServer) service..." "WARN"
    Stop-Service -Name LanmanServer -Force -ErrorAction Stop
    Start-Sleep -Seconds 3
    Start-Service -Name LanmanServer -ErrorAction Stop
    Start-Sleep -Seconds 2

    $svc = Get-Service -Name LanmanServer
    if ($svc.Status -eq "Running") {
        Write-Log "Server service restarted successfully" "SUCCESS"
    } else {
        Write-Log ("Server service status: " + $svc.Status) "ERROR"
    }
} catch {
    Write-Log ("Server service restart failed: " + $_.Exception.Message) "ERROR"
    Write-Log "Try manually: net stop server && net start server" "WARN"
}

# Also restart Workstation service for good measure
try {
    Restart-Service -Name LanmanWorkstation -Force -ErrorAction SilentlyContinue
    Write-Log "Workstation service restarted" "SUCCESS"
} catch {
    Write-Log "Workstation service restart skipped" "WARN"
}

# ==============================================================================
# SECTION 9 -- VERIFY ALL SETTINGS ARE CORRECTLY APPLIED
# ==============================================================================
Write-Log "--- SECTION 9: Verification ---"

$allPass = $true

# Registry checks
$checks = @(
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa";                              Name = "RestrictAnonymous";              Expected = 0 },
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa";                              Name = "RestrictAnonymousSAM";           Expected = 0 },
    @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa";                              Name = "EveryoneIncludesAnonymous";      Expected = 1 },
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";         Name = "LocalAccountTokenFilterPolicy";  Expected = 1 }
)

foreach ($chk in $checks) {
    try {
        $val = (Get-ItemProperty -Path $chk.Path -Name $chk.Name -ErrorAction Stop).($chk.Name)
        if ($val -eq $chk.Expected) {
            Write-Log ("[PASS] " + $chk.Name + " = " + $val) "SUCCESS"
        } else {
            Write-Log ("[FAIL] " + $chk.Name + " = " + $val + " (expected " + $chk.Expected + ")") "ERROR"
            $allPass = $false
        }
    } catch {
        Write-Log ("[FAIL] Could not read " + $chk.Name + ": " + $_.Exception.Message) "ERROR"
        $allPass = $false
    }
}

# NullSessionPipes check
try {
    $pipes = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" `
        -Name "NullSessionPipes" -ErrorAction Stop).NullSessionPipes
    if ($pipes -contains "samr") {
        Write-Log ("[PASS] NullSessionPipes contains samr: " + ($pipes -join ",")) "SUCCESS"
    } else {
        Write-Log ("[FAIL] NullSessionPipes missing samr. Current: " + ($pipes -join ",")) "ERROR"
        $allPass = $false
    }
} catch {
    Write-Log ("[FAIL] NullSessionPipes not set") "ERROR"
    $allPass = $false
}

# Share exists check
$sh = Get-SmbShare -Name "BackupShare" -ErrorAction SilentlyContinue
if ($null -ne $sh) {
    Write-Log "[PASS] BackupShare exists" "SUCCESS"
} else {
    Write-Log "[FAIL] BackupShare not found" "ERROR"
    $allPass = $false
}

# SMB signing check
$smbCfg = Get-SmbServerConfiguration
if (-not $smbCfg.RequireSecuritySignature) {
    Write-Log "[PASS] SMB signing not required" "SUCCESS"
} else {
    Write-Log "[WARN] SMB signing is required -- may still cause issues" "WARN"
}

# Server service running check
$svc = Get-Service -Name LanmanServer
if ($svc.Status -eq "Running") {
    Write-Log "[PASS] LanmanServer (SMB) service is Running" "SUCCESS"
} else {
    Write-Log ("[FAIL] LanmanServer status: " + $svc.Status) "ERROR"
    $allPass = $false
}

# ==============================================================================
# FINAL OUTPUT + WHAT TO RUN FROM KALI
# ==============================================================================
$ip = (Get-NetIPAddress -AddressFamily IPv4 |
    Where-Object { $_.IPAddress -ne "127.0.0.1" -and $_.PrefixOrigin -ne "WellKnown" } |
    Select-Object -First 1).IPAddress

Write-Host ""
Write-Host "=================================================================" -ForegroundColor Cyan
if ($allPass) {
    Write-Host "  ALL CHECKS PASSED -- NULL SESSION SHOULD NOW WORK" -ForegroundColor Green
} else {
    Write-Host "  SOME CHECKS FAILED -- REVIEW ERRORS ABOVE" -ForegroundColor Yellow
    Write-Host "  If failures persist, reboot the VM and re-run this script." -ForegroundColor Yellow
}
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Target IP : $ip" -ForegroundColor White
Write-Host ""
Write-Host "  Now run these from Kali Linux:" -ForegroundColor White
Write-Host ""
Write-Host "  # List shares (null session)" -ForegroundColor Gray
Write-Host ("  smbclient -L //" + $ip + " -N -m SMB2") -ForegroundColor Green
Write-Host ""
Write-Host "  # Enumerate everything" -ForegroundColor Gray
Write-Host ("  enum4linux -a " + $ip) -ForegroundColor Green
Write-Host ""
Write-Host "  # CrackMapExec null session" -ForegroundColor Gray
Write-Host ("  crackmapexec smb " + $ip + " -u '' -p '' --shares") -ForegroundColor Green
Write-Host ""
Write-Host "  # Access BackupShare directly" -ForegroundColor Gray
Write-Host ("  smbclient //" + $ip + "/BackupShare -N -m SMB2") -ForegroundColor Green
Write-Host ""
Write-Host "  # rpcclient user enumeration" -ForegroundColor Gray
Write-Host ("  rpcclient -U '' -N " + $ip + " -c 'enumdomusers'") -ForegroundColor Green
Write-Host ""
Write-Host "  NOTE: If still denied after this script, REBOOT the VM." -ForegroundColor Yellow
Write-Host "  Some LSA changes only take full effect after a reboot." -ForegroundColor Yellow
Write-Host ""
