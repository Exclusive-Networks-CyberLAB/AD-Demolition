  <#
.SYNOPSIS
    CyberLAB AD Lab Builder (config-driven, profiles 1-4).
  
.DESCRIPTION
    Builds a CyberLAB OU tree, groups, users, and optional misconfigurations
    based on external config files (JSON + CSV).
  
    Config files:
      - ad-config.json : OUs, groups, profiles, misconfig IDs
      - users.csv      : user list and baseline group membership
  
    Profiles (defined in ad-config.json):
      1 - Secure Baseline
      2 - Real-World Mess
      3 - Attack Playground
      4 - DC Chaos Mode (Profile 3 + DC-level misconfigs)
  
    WARNING: This is for lab/demo environments only.
             DO NOT run in production.
  
.PARAMETER ConfigPath
    Path to folder containing ad-config.json and users.csv.
    Default: .\Configs\Default
  
.PARAMETER Profile
    Profile number to apply (1/2/3/4). If omitted, you'll be prompted.
  
#>
  
[CmdletBinding()]
param(
    [string]$ConfigPath = ".\Configs\Default",
    [int]$Profile
)
  
# ---------------------------
# Global summary
# ---------------------------
  
$Global:LabSummary = @{
    OUsCreated    = 0
    GroupsCreated = 0
    UsersCreated  = 0
}
  
# ---------------------------
# Helper output
# ---------------------------
  
function Write-Info {
    param([string]$Message)
    Write-Host "[*] $Message" -ForegroundColor Cyan
}
  
function Write-WarnMsg {
    param([string]$Message)
    Write-Host "[!] $Message" -ForegroundColor Yellow
}
  
function Write-ErrorMsg {
    param([string]$Message)
    Write-Host "[X] $Message" -ForegroundColor Red
}
  
# ---------------------------
# AD helpers
# ---------------------------
  
function Ensure-ADModule {
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
    }
    catch {
        Write-ErrorMsg "Failed to import ActiveDirectory module. Install RSAT / AD tools and try again."
        throw
    }
}
  
function Get-DomainContext {
    param(
        [System.Management.Automation.PSCredential]$Credential
    )
  
    try {
        if ($Credential) {
            $domain = Get-ADDomain -Credential $Credential -ErrorAction Stop
        } else {
            $domain = Get-ADDomain -ErrorAction Stop
        }
    }
    catch {
        Write-ErrorMsg "Could not detect Active Directory domain. Are you connected to a domain and running with sufficient rights?"
        throw
    }
  
    return $domain
}
  
function Get-LabRootOuDn {
    param(
        [string]$LabRootOuName,
        [string]$DomainDn,
        [System.Management.Automation.PSCredential]$Credential
    )
  
    $rootOuDn = "OU=$LabRootOuName,$DomainDn"
  
    try {
        if ($Credential) {
            $existing = Get-ADOrganizationalUnit -LDAPFilter "(ou=$LabRootOuName)" -SearchBase $DomainDn -Credential $Credential -ErrorAction SilentlyContinue
        } else {
            $existing = Get-ADOrganizationalUnit -LDAPFilter "(ou=$LabRootOuName)" -SearchBase $DomainDn -ErrorAction SilentlyContinue
        }
  
        if (-not $existing) {
            Write-Info "Creating root lab OU: $rootOuDn"
            if ($Credential) {
                New-ADOrganizationalUnit -Name $LabRootOuName -Path $DomainDn -ProtectedFromAccidentalDeletion $true -Credential $Credential | Out-Null
            } else {
                New-ADOrganizationalUnit -Name $LabRootOuName -Path $DomainDn -ProtectedFromAccidentalDeletion $true | Out-Null
            }
            $Global:LabSummary.OUsCreated++
        }
    }
    catch {
        Write-ErrorMsg "Failed to create or retrieve root OU $rootOuDn. $_"
        throw
    }
  
    return $rootOuDn
}
  
function Ensure-LabOuPath {
    param(
        [string]$RelativePath,   # e.g. "Corp/Users/IT"
        [string]$RootOuName,
        [string]$DomainDn,
        [System.Management.Automation.PSCredential]$Credential
    )
  
    $currentDn = Get-LabRootOuDn -LabRootOuName $RootOuName -DomainDn $DomainDn -Credential $Credential
  
    if ([string]::IsNullOrWhiteSpace($RelativePath)) {
        return $currentDn
    }
  
    # Normalise slashes
    $pathNorm = $RelativePath.Replace('\', '/')
    $elements = $pathNorm -split "/"
  
    foreach ($elem in $elements) {
        $elemTrim = $elem.Trim()
        if ([string]::IsNullOrWhiteSpace($elemTrim)) { continue }
  
        $nextDn = "OU=$elemTrim,$currentDn"
  
        try {
            if ($Credential) {
                $ou = Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$nextDn'" -Credential $Credential -ErrorAction SilentlyContinue
            } else {
                $ou = Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$nextDn'" -ErrorAction SilentlyContinue
            }
  
            if (-not $ou) {
                Write-Info "Creating OU: $nextDn"
                if ($Credential) {
                    New-ADOrganizationalUnit -Name $elemTrim -Path $currentDn -ProtectedFromAccidentalDeletion $false -Credential $Credential | Out-Null
                } else {
                    New-ADOrganizationalUnit -Name $elemTrim -Path $currentDn -ProtectedFromAccidentalDeletion $false | Out-Null
                }
                $Global:LabSummary.OUsCreated++
            }
  
            $currentDn = $nextDn
        }
        catch {
            Write-ErrorMsg "Failed to create or retrieve OU $nextDn. $_"
            throw
        }
    }
  
    return $currentDn
}
  
function Ensure-LabGroups {
    param(
        [array]$Groups,
        [string]$RootOuName,
        [string]$DomainDn,
        [System.Management.Automation.PSCredential]$Credential
    )
  
    $groupsOuDn = Ensure-LabOuPath -RelativePath "Groups" -RootOuName $RootOuName -DomainDn $DomainDn -Credential $Credential
  
    foreach ($g in $Groups) {
        $name = $g.Name
        $description = $g.Description
  
        try {
            if ($Credential) {
                $existing = Get-ADGroup -Filter "Name -eq '$name'" -Credential $Credential -ErrorAction SilentlyContinue
            } else {
                $existing = Get-ADGroup -Filter "Name -eq '$name'" -ErrorAction SilentlyContinue
            }
  
            if (-not $existing) {
                Write-Info "Creating group: $name"
                $params = @{
                    Name          = $name
                    GroupScope    = "Global"
                    GroupCategory = "Security"
                    Path          = $groupsOuDn
                    Description   = $description
                }
                if ($Credential) { $params.Credential = $Credential }
  
                New-ADGroup @params | Out-Null
                $Global:LabSummary.GroupsCreated++
            }
            else {
                Write-Info "Group already exists: $name (skipping create)"
            }
        }
        catch {
            Write-ErrorMsg "Failed to create or check group $name. $_"
        }
    }
  
    # Baseline nesting: IT Admins -> Domain Admins (good admin model anchor)
    try {
        Write-Info "Ensuring 'IT Admins' is a member of 'Domain Admins' (baseline admin model)"
        if ($Credential) {
            Add-ADGroupMember -Identity "Domain Admins" -Members "IT Admins" -Credential $Credential -ErrorAction SilentlyContinue
        } else {
            Add-ADGroupMember -Identity "Domain Admins" -Members "IT Admins" -ErrorAction SilentlyContinue
        }
    }
    catch {
        Write-WarnMsg "Could not add IT Admins to Domain Admins (might already be a member). $_"
    }
}
  
function Ensure-LabUsers {
    param(
        [array]$Users,
        [string]$RootOuName,
        [string]$DomainDn,
        [string]$DnsRoot,
        [System.Security.SecureString]$DefaultPassword,
        [System.Management.Automation.PSCredential]$Credential
    )
  
    foreach ($u in $Users) {
  
        # Skip blank/comment-style rows if present
        if (-not $u.SamAccountName -or $u.SamAccountName.Trim().StartsWith("#")) {
            continue
        }
  
        $sam       = $u.SamAccountName.Trim()
        $ouRelPath = $u.OuPath.Trim()
        $ouDn      = Ensure-LabOuPath -RelativePath $ouRelPath -RootOuName $RootOuName -DomainDn $DomainDn -Credential $Credential
        $upn       = "$sam@$DnsRoot"
        $display   = $u.DisplayName
        $given     = $u.GivenName
        $surname   = $u.Surname
  
        $isSvc = $false
        if ($u.IsServiceAccount) {
            [bool]::TryParse($u.IsServiceAccount.ToString(), [ref]$isSvc) | Out-Null
        }
  
        $baselineGroups = @()
        if ($u.BaselineGroups) {
            $baselineGroups = $u.BaselineGroups -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }
        }
  
        try {
            if ($Credential) {
                $existingUser = Get-ADUser -Filter "SamAccountName -eq '$sam'" -Credential $Credential -ErrorAction SilentlyContinue
            } else {
                $existingUser = Get-ADUser -Filter "SamAccountName -eq '$sam'" -ErrorAction SilentlyContinue
            }
  
            if (-not $existingUser) {
                Write-Info "Creating user: $sam in $ouDn"
  
                $params = @{
                    Name                  = $display
                    SamAccountName        = $sam
                    GivenName             = $given
                    Surname               = $surname
                    DisplayName           = $display
                    UserPrincipalName     = $upn
                    AccountPassword       = $DefaultPassword
                    Enabled               = $true
                    ChangePasswordAtLogon = $true
                    Path                  = $ouDn
                }
  
                if ($isSvc) {
                    # Service accounts: no forced change at logon
                    $params.ChangePasswordAtLogon = $false
                }
  
                if ($Credential) { $params.Credential = $Credential }
  
                New-ADUser @params | Out-Null
                $Global:LabSummary.UsersCreated++
            }
            else {
                Write-Info "User already exists: $sam (will still ensure group membership)"
            }
  
            foreach ($g in $baselineGroups) {
                try {
                    if ($Credential) {
                        Add-ADGroupMember -Identity $g -Members $sam -Credential $Credential -ErrorAction SilentlyContinue
                    } else {
                        Add-ADGroupMember -Identity $g -Members $sam -ErrorAction SilentlyContinue
                    }
                }
                catch {
                    Write-WarnMsg "Could not add $sam to group $g. $_"
                }
            }
        }
        catch {
            Write-ErrorMsg "Failed to create or update user $sam. $_"
        }
    }
}
  
# ---------------------------
# Password / Lockout policies
# ---------------------------
  
function Set-DomainPasswordPolicyFromProfile {
    param(
        $PasswordPolicy,
        [System.Management.Automation.PSCredential]$Credential
    )
  
    if (-not $PasswordPolicy) {
        Write-Info "No password policy block in profile; skipping password changes."
        return
    }
  
    try {
        Write-Info "Applying domain password & lockout policy from profile ..."
  
        # Get current default domain password policy as Identity
        if ($Credential) {
            $pwdObj = Get-ADDefaultDomainPasswordPolicy -Credential $Credential -ErrorAction Stop
        } else {
            $pwdObj = Get-ADDefaultDomainPasswordPolicy -ErrorAction Stop
        }
  
        # Pull values out of the profile and normalise to ints
        $minLength   = [int]($PasswordPolicy.MinLength)
        $maxAgeDays  = [int]($PasswordPolicy.MaxAgeDays)
        $history     = [int]($PasswordPolicy.HistoryCount)
        $complex     = [bool]($PasswordPolicy.ComplexityEnabled)
  
        $lockThreshold    = [int]($PasswordPolicy.LockoutThreshold)
        $lockDurationMins = [int]($PasswordPolicy.LockoutDurationMinutes)
        $lockObsMins      = [int]($PasswordPolicy.ResetLockoutCounterMinutes)
  
        # Build parameter set
        $params = @{
            Identity             = $pwdObj
            ComplexityEnabled    = $complex
            MinPasswordLength    = $minLength
            PasswordHistoryCount = $history
            LockoutThreshold     = $lockThreshold
        }
  
        if ($maxAgeDays -gt 0) {
            $params.MaxPasswordAge = New-TimeSpan -Days $maxAgeDays
        } else {
            $params.MaxPasswordAge = [TimeSpan]::Zero
        }
  
        # Lockout durations: 0 means "no lockout"
        if ($lockDurationMins -gt 0) {
            $params.LockoutDuration = New-TimeSpan -Minutes $lockDurationMins
        } else {
            $params.LockoutDuration = [TimeSpan]::Zero
        }
  
        if ($lockObsMins -gt 0) {
            $params.LockoutObservationWindow = New-TimeSpan -Minutes $lockObsMins
        } else {
            $params.LockoutObservationWindow = [TimeSpan]::Zero
        }
  
        if ($Credential) { $params.Credential = $Credential }
  
        Set-ADDefaultDomainPasswordPolicy @params -ErrorAction SilentlyContinue
    }
    catch {
        Write-WarnMsg "Could not apply domain password/lockout policy. $_"
    }
}
  
# ---------------------------
# Misconfig helpers (user/group)
# ---------------------------
  
function Invoke-Misconfig_PwdNeverExpires_ServiceAccounts {
    param($Credential)
  
    Write-Info "Setting PasswordNeverExpires for service accounts ..."
    $svcAccounts = @("svc_sql","svc_backup","svc_web","svc_monitor")
    foreach ($s in $svcAccounts) {
        try {
            if ($Credential) {
                Set-ADUser -Identity $s -PasswordNeverExpires $true -Credential $Credential -ErrorAction SilentlyContinue
            } else {
                Set-ADUser -Identity $s -PasswordNeverExpires $true -ErrorAction SilentlyContinue
            }
        }
        catch {
            Write-WarnMsg "Failed to set PasswordNeverExpires for $s. $_"
        }
    }
}
  
function Invoke-Misconfig_PwdNeverExpires_SomeAdmins {
    param($Credential)
  
    Write-Info "Setting PasswordNeverExpires for selected privileged admins ..."
    $targets = @("itadmin1","breakglassadmin")
    foreach ($t in $targets) {
        try {
            if ($Credential) {
                Set-ADUser -Identity $t -PasswordNeverExpires $true -Credential $Credential -ErrorAction SilentlyContinue
            } else {
                Set-ADUser -Identity $t -PasswordNeverExpires $true -ErrorAction SilentlyContinue
            }
        }
        catch {
            Write-WarnMsg "Failed to set PasswordNeverExpires for $t. $_"
        }
    }
}
  
function Invoke-Misconfig_Overbroad_LocalAdmin_Workstations_RemoteAccessUsers {
    param($Credential)
  
    Write-Info "Adding 'Remote Access Users' to 'Local Admin - Workstations' ..."
    try {
        if ($Credential) {
            Add-ADGroupMember -Identity "Local Admin - Workstations" -Members "Remote Access Users" -Credential $Credential -ErrorAction SilentlyContinue
        } else {
            Add-ADGroupMember -Identity "Local Admin - Workstations" -Members "Remote Access Users" -ErrorAction SilentlyContinue
        }
    }
    catch {
        Write-WarnMsg "Could not nest Remote Access Users into Local Admin - Workstations. $_"
    }
}
  
function Invoke-Misconfig_Overbroad_LocalAdmin_Workstations_AllStaff {
    param($Credential)
  
    Write-Info "Adding 'All Staff' to 'Local Admin - Workstations' (everyone is local admin on workstations) ..."
    try {
        if ($Credential) {
            Add-ADGroupMember -Identity "Local Admin - Workstations" -Members "All Staff" -Credential $Credential -ErrorAction SilentlyContinue
        } else {
            Add-ADGroupMember -Identity "Local Admin - Workstations" -Members "All Staff" -ErrorAction SilentlyContinue
        }
    }
    catch {
        Write-WarnMsg "Could not nest All Staff into Local Admin - Workstations. $_"
    }
}
  
function Invoke-Misconfig_HelpdeskIn_DomainAdmins {
    param($Credential)
  
    Write-Info "Adding 'Helpdesk Tier 1' to 'Domain Admins' ..."
    try {
        if ($Credential) {
            Add-ADGroupMember -Identity "Domain Admins" -Members "Helpdesk Tier 1" -Credential $Credential -ErrorAction SilentlyContinue
        } else {
            Add-ADGroupMember -Identity "Domain Admins" -Members "Helpdesk Tier 1" -ErrorAction SilentlyContinue
        }
    }
    catch {
        Write-WarnMsg "Could not add Helpdesk Tier 1 to Domain Admins. $_"
    }
}
  
function Invoke-Misconfig_ServiceAccounts_In_DomainAdmins {
    param($Credential)
  
    Write-Info "Adding service accounts to 'Domain Admins' ..."
    $svcAccounts = @("svc_sql","svc_backup","svc_web","svc_monitor")
    foreach ($s in $svcAccounts) {
        try {
            if ($Credential) {
                Add-ADGroupMember -Identity "Domain Admins" -Members $s -Credential $Credential -ErrorAction SilentlyContinue
            } else {
                Add-ADGroupMember -Identity "Domain Admins" -Members $s -ErrorAction SilentlyContinue
            }
        }
        catch {
            Write-WarnMsg "Could not add $s to Domain Admins. $_"
        }
    }
}
  
function Invoke-Misconfig_StalePrivilegedAccount_OldAdmin {
    param($Credential)
  
    Write-Info "Disabling 'oldadmin' but keeping privileged membership ..."
    try {
        if ($Credential) {
            Set-ADUser -Identity "oldadmin" -Enabled $false -Credential $Credential -ErrorAction SilentlyContinue
        } else {
            Set-ADUser -Identity "oldadmin" -Enabled $false -ErrorAction SilentlyContinue
        }
  
        if ($Credential) {
            Add-ADGroupMember -Identity "Domain Admins" -Members "oldadmin" -Credential $Credential -ErrorAction SilentlyContinue
        } else {
            Add-ADGroupMember -Identity "Domain Admins" -Members "oldadmin" -ErrorAction SilentlyContinue
        }
    }
    catch {
        Write-WarnMsg "Could not fully apply stale privileged account misconfig for oldadmin. $_"
    }
}
  
function Invoke-Misconfig_SharedAccounts_Helpdesk {
    param($Credential)
  
    Write-Info "Configuring shared-style helpdesk account with broad access ..."
    # We'll use helpdesk1 as the shared-style account and over-privilege it
    try {
        if ($Credential) {
            Set-ADUser -Identity "helpdesk1" -PasswordNeverExpires $true -Credential $Credential -ErrorAction SilentlyContinue
        } else {
            Set-ADUser -Identity "helpdesk1" -PasswordNeverExpires $true -ErrorAction SilentlyContinue
        }
  
        # Extra memberships: Remote Access Users + Local Admin - Servers
        $extraGroups = @("Remote Access Users","Local Admin - Servers")
        foreach ($g in $extraGroups) {
            try {
                if ($Credential) {
                    Add-ADGroupMember -Identity $g -Members "helpdesk1" -Credential $Credential -ErrorAction SilentlyContinue
                } else {
                    Add-ADGroupMember -Identity $g -Members "helpdesk1" -ErrorAction SilentlyContinue
                }
            }
            catch {
                Write-WarnMsg "Could not add helpdesk1 to $g. $_"
            }
        }
    }
    catch {
        Write-WarnMsg "Could not apply shared helpdesk misconfig. $_"
    }
}
  
# ---------------------------
# DC detection helper
# ---------------------------
  
function Test-IsDomainController {
    try {
        $dc = Get-ADDomainController -Identity $env:COMPUTERNAME -ErrorAction Stop
        return $true
    }
    catch {
        return $false
    }
}
  
# ---------------------------
# DC Chaos misconfigs
# ---------------------------
  
function Invoke-Misconfig_DC_EnablePrintSpooler {
    if (-not (Test-IsDomainController)) {
        Write-WarnMsg "Not running on a DC; skipping Print Spooler enable."
        return
    }
  
    Write-WarnMsg "Enabling Print Spooler service on Domain Controller ..."
    Set-Service -Name Spooler -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service -Name Spooler -ErrorAction SilentlyContinue
}
  
function Invoke-Misconfig_DC_EnableSMBv1 {
    if (-not (Test-IsDomainController)) {
        Write-WarnMsg "Not running on a DC; skipping SMBv1 enable."
        return
    }
  
    Write-WarnMsg "Enabling SMBv1 on Domain Controller ..."
    Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue | Out-Null
    Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force -ErrorAction SilentlyContinue
}
  
function Invoke-Misconfig_DC_DisableSMBSigning {
    if (-not (Test-IsDomainController)) {
        Write-WarnMsg "Not running on a DC; skipping SMB signing disable."
        return
    }
  
    Write-WarnMsg "Disabling SMB signing on Domain Controller ..."
    Set-SmbServerConfiguration -RequireSecuritySignature $false -EnableSecuritySignature $false -Force -ErrorAction SilentlyContinue
}
  
function Invoke-Misconfig_DC_EnableLLMNR_NetBIOS {
    if (-not (Test-IsDomainController)) {
        Write-WarnMsg "Not running on DC; skipping LLMNR/NetBIOS."
        return
    }
  
    Write-WarnMsg "Enabling LLMNR and NetBIOS on Domain Controller ..."
  
    $dnsClientKey = "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient"
  
    try {
        # Ensure the DNSClient policy key exists
        if (-not (Test-Path $dnsClientKey)) {
            New-Item -Path $dnsClientKey -Force | Out-Null
        }
  
        # Enable multicast (LLMNR)
        New-ItemProperty `
            -Path $dnsClientKey `
            -Name EnableMulticast `
            -PropertyType DWord `
            -Value 1 `
            -Force | Out-Null
    }
    catch {
        Write-WarnMsg "Could not set LLMNR policy registry value. $_"
    }
  
    # Enable NetBIOS over TCP/IP on all IP-enabled adapters
    try {
        Get-WmiObject Win32_NetworkAdapterConfiguration |
            Where-Object { $_.IPEnabled } |
            ForEach-Object {
                $_.SetTcpipNetbios(1) | Out-Null   # 1 = Enable NetBIOS
            }
    }
    catch {
        Write-WarnMsg "Could not enable NetBIOS on one or more adapters. $_"
    }
}
  
  
function Invoke-Misconfig_DC_WeakenLDAPSecurity {
    if (-not (Test-IsDomainController)) {
        Write-WarnMsg "Not on DC; skipping LDAP weakening."
        return
    }
  
    Write-WarnMsg "Disabling LDAP signing & channel binding ..."
  
    Set-ItemProperty `
      -Path "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters" `
      -Name "LDAPServerIntegrity" `
      -Value 1
  
    Set-ItemProperty `
      -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" `
      -Name "LdapEnforceChannelBinding" `
      -Value 0
}
  
function Invoke-Misconfig_DC_EnableLegacyNTLM {
    if (-not (Test-IsDomainController)) {
        Write-WarnMsg "Not on DC; skipping NTLM downgrade."
        return
    }
  
    Write-WarnMsg "Weakening NTLM authentication policy ..."
    Set-ItemProperty `
      -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
      -Name LmCompatibilityLevel `
      -Value 1
}
  
function Invoke-Misconfig_DC_DisableFirewall {
    if (-not (Test-IsDomainController)) {
        Write-WarnMsg "Not on DC; skipping firewall disable."
        return
    }
  
    Write-WarnMsg "Disabling Windows Firewall on Domain Controller ..."
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False -ErrorAction SilentlyContinue
}
  
function Invoke-Misconfig_DC_WeakenDefender {
    if (-not (Test-IsDomainController)) {
        Write-WarnMsg "Not on DC; skipping Defender weakening."
        return
    }
  
    Write-WarnMsg "Weakening Microsoft Defender on Domain Controller ..."
    try { Set-MpPreference -DisableRealtimeMonitoring $true }       catch {}
    try { Set-MpPreference -DisableIOAVProtection $true }           catch {}
    try { Set-MpPreference -DisableBehaviorMonitoring $true }       catch {}
}
  
function Invoke-Misconfig_DC_RelaxAuditAndLogRetention {
    if (-not (Test-IsDomainController)) {
        Write-WarnMsg "Not on DC; skipping audit weakening."
        return
    }
  
    Write-WarnMsg "Weakening security audit logging on Domain Controller ..."
  
    try {
        wevtutil sl Security /ms:32768 | Out-Null
        auditpol /set /subcategory:"Logon" /success:disable /failure:disable | Out-Null
        auditpol /set /subcategory:"Kerberos Authentication Service" /success:disable /failure:disable | Out-Null
        auditpol /set /subcategory:"Directory Service Access" /success:disable /failure:disable | Out-Null
    }
    catch {
        Write-WarnMsg "Failed to weaken some audit policies. $_"
    }
}
  
function Invoke-Misconfig_DC_ExposeRPCAndSMB {
    if (-not (Test-IsDomainController)) {
        Write-WarnMsg "Not on DC; skipping RPC/SMB exposure."
        return
    }
  
    Write-WarnMsg "Opening RPC and SMB on Domain Controller firewall ..."
  
    New-NetFirewallRule -DisplayName "DC Open SMB" -Protocol TCP -LocalPort 445 -Action Allow -Direction Inbound -ErrorAction SilentlyContinue | Out-Null
    New-NetFirewallRule -DisplayName "DC Open RPC" -Protocol TCP -LocalPort 135 -Action Allow -Direction Inbound -ErrorAction SilentlyContinue | Out-Null
}
  
function Invoke-Misconfig_DC_WeakenSysvolACL {
    if (-not (Test-IsDomainController)) {
        Write-WarnMsg "Not on DC; skipping SYSVOL ACL weakening."
        return
    }
  
    $sysvol = "$env:SystemRoot\SYSVOL\sysvol"
    Write-WarnMsg "Weakening SYSVOL permissions at $sysvol ..."
  
    try {
        icacls $sysvol /grant "Authenticated Users:(OI)(CI)M" /T | Out-Null
    }
    catch {
        Write-WarnMsg "Failed to weaken SYSVOL ACLs. $_"
    }
}
  
# ---------------------------
# Misconfig orchestrator
# ---------------------------
  
function Apply-Misconfigurations {
    param(
        $ProfileConfig,
        [System.Management.Automation.PSCredential]$Credential
    )
  
    if (-not $ProfileConfig.MisconfigIds -or $ProfileConfig.MisconfigIds.Count -eq 0) {
        Write-Info "Profile has no misconfig IDs; skipping misconfiguration overlay."
        return
    }
  
    Write-WarnMsg "Applying misconfigurations for profile [$($ProfileConfig.Name)] ..."
    Write-WarnMsg "These changes are intentionally insecure and for lab use only."
  
    foreach ($id in $ProfileConfig.MisconfigIds) {
        switch ($id) {
            "PwdNeverExpires_ServiceAccounts" {
                Invoke-Misconfig_PwdNeverExpires_ServiceAccounts -Credential $Credential
            }
            "PwdNeverExpires_SomeAdmins" {
                Invoke-Misconfig_PwdNeverExpires_SomeAdmins -Credential $Credential
            }
            "Overbroad_LocalAdmin_Workstations_RemoteAccessUsers" {
                Invoke-Misconfig_Overbroad_LocalAdmin_Workstations_RemoteAccessUsers -Credential $Credential
            }
            "Overbroad_LocalAdmin_Workstations_AllStaff" {
                Invoke-Misconfig_Overbroad_LocalAdmin_Workstations_AllStaff -Credential $Credential
            }
            "HelpdeskIn_DomainAdmins" {
                Invoke-Misconfig_HelpdeskIn_DomainAdmins -Credential $Credential
            }
            "ServiceAccounts_In_DomainAdmins" {
                Invoke-Misconfig_ServiceAccounts_In_DomainAdmins -Credential $Credential
            }
            "StalePrivilegedAccount_OldAdmin" {
                Invoke-Misconfig_StalePrivilegedAccount_OldAdmin -Credential $Credential
            }
            "SharedAccounts_Helpdesk" {
                Invoke-Misconfig_SharedAccounts_Helpdesk -Credential $Credential
            }
  
            "DC_EnablePrintSpooler" {
                Invoke-Misconfig_DC_EnablePrintSpooler
            }
            "DC_EnableSMBv1" {
                Invoke-Misconfig_DC_EnableSMBv1
            }
            "DC_DisableSMBSigning" {
                Invoke-Misconfig_DC_DisableSMBSigning
            }
            "DC_EnableLLMNR_NetBIOS" {
                Invoke-Misconfig_DC_EnableLLMNR_NetBIOS
            }
            "DC_WeakenLDAPSecurity" {
                Invoke-Misconfig_DC_WeakenLDAPSecurity
            }
            "DC_EnableLegacyNTLM" {
                Invoke-Misconfig_DC_EnableLegacyNTLM
            }
            "DC_DisableFirewall" {
                Invoke-Misconfig_DC_DisableFirewall
            }
            "DC_WeakenDefender" {
                Invoke-Misconfig_DC_WeakenDefender
            }
            "DC_RelaxAuditAndLogRetention" {
                Invoke-Misconfig_DC_RelaxAuditAndLogRetention
            }
            "DC_ExposeRPCAndSMB" {
                Invoke-Misconfig_DC_ExposeRPCAndSMB
            }
            "DC_WeakenSysvolACL" {
                Invoke-Misconfig_DC_WeakenSysvolACL
            }
            default {
                Write-WarnMsg "Unknown MisconfigId '$id' in profile; no handler implemented."
            }
        }
    }
  
    Write-WarnMsg "Misconfiguration overlay complete for profile [$($ProfileConfig.Name)]."
}
  
# ---------------------------
# Summary
# ---------------------------
  
function Show-LabSummary {
    param(
        [string]$LabRootOuName,
        [object]$ProfileConfig
    )
  
    Write-Host ""
    Write-Host "===== CyberLAB AD Lab Summary =====" -ForegroundColor Green
    Write-Host "Lab Root OU:    OU=$LabRootOuName"
    Write-Host "OUs created:    $($Global:LabSummary.OUsCreated)"
    Write-Host "Groups created: $($Global:LabSummary.GroupsCreated)"
    Write-Host "Users created:  $($Global:LabSummary.UsersCreated)"
    Write-Host ""
    Write-Host "Profile:        $($ProfileConfig.Name)"
    Write-Host "Description:    $($ProfileConfig.Description)"
    Write-Host ""
    Write-Host "NOTE: This environment is intended for CyberLAB demos only. Do not use in production." -ForegroundColor Yellow
    Write-Host "====================================" -ForegroundColor Green
}
  
# ---------------------------
# MAIN
# ---------------------------
  
Write-Host "CyberLAB AD Lab Builder (config-driven, Profiles 1-4)" -ForegroundColor Magenta
Write-Host "WARNING: For lab/demo environments only. Do NOT run in production." -ForegroundColor Yellow
Write-Host ""
  
Ensure-ADModule
  
# Load config files
$adConfigPath = Join-Path $ConfigPath "ad-config.json"
$usersCsvPath = Join-Path $ConfigPath "users.csv"
  
if (-not (Test-Path $adConfigPath)) {
    Write-ErrorMsg "Config file not found: $adConfigPath"
    exit 1
}
if (-not (Test-Path $usersCsvPath)) {
    Write-ErrorMsg "Users CSV not found: $usersCsvPath"
    exit 1
}
  
Write-Info "Loading AD configuration from $adConfigPath"
$configJson = Get-Content $adConfigPath -Raw | ConvertFrom-Json
  
$labRootOuName = $configJson.LabRootOuName
$ouList        = $configJson.OUs
$groupList     = $configJson.Groups
$profiles      = $configJson.Profiles
  
Write-Info "Loading users from $usersCsvPath"
$users = Import-Csv $usersCsvPath
  
if ($users.Count -eq 0) {
    Write-WarnMsg "Users CSV imported 0 rows. No lab users will be created!"
}
  
# Prompt for domain credentials
Write-Info "Please enter domain credentials (ideally a domain admin account)."
$cred = Get-Credential -Message "Enter domain admin credentials"
  
# Get domain context
$domain   = Get-DomainContext -Credential $cred
$domainDn = $domain.DistinguishedName
$dnsRoot  = $domain.DNSRoot
  
Write-Info "Detected domain: $($domain.Name) ($dnsRoot)"
Write-Info "Domain DN: $domainDn"
Write-Host ""
  
# Safety check: prod vs lab
if ($domain.Name -notmatch "lab|demo|test|cyber|example") {
    Write-WarnMsg "Domain does not look like a lab/demo domain. Make sure you are NOT on production."
    $confirm = Read-Host "Type 'YES' to continue anyway, or anything else to abort"
    if ($confirm -ne "YES") {
        Write-ErrorMsg "Aborting at user request."
        exit 1
    }
}
  
# Choose profile if not provided
if (-not $Profile -or $Profile -lt 1 -or $Profile -gt 4) {
    Write-Host "Available profiles:" -ForegroundColor Cyan
    foreach ($key in $profiles.PSObject.Properties.Name | Sort-Object {[int]$_}) {
        $p = $profiles.$key
        Write-Host "  $key) $($p.Name) - $($p.Description)"
    }
    $inputProfile = Read-Host "Enter profile number [default: 1]"
    if ([string]::IsNullOrWhiteSpace($inputProfile)) {
        $Profile = 1
    } else {
        [int]::TryParse($inputProfile, [ref]$Profile) | Out-Null
        if ($Profile -lt 1 -or $Profile -gt 4) { $Profile = 1 }
    }
}
  
# Validate profile
$profileKey = "$Profile"
if (-not $profiles.$profileKey) {
    Write-WarnMsg "Profile $Profile not found in config; defaulting to profile 1."
    $profileKey = "1"
}
$profileConfig = $profiles.$profileKey
  
Write-Host ""
Write-Info "Using profile: $($profileConfig.Name)"
  
# Apply password / lockout policy per profile
Set-DomainPasswordPolicyFromProfile -PasswordPolicy $profileConfig.PasswordPolicy -Credential $cred
  
# Build OU structure
Write-Info "Creating OU structure under OU=$labRootOuName,$domainDn ..."
foreach ($ou in $ouList) {
    [void] (Ensure-LabOuPath -RelativePath $ou.Path -RootOuName $labRootOuName -DomainDn $domainDn -Credential $cred)
}
  
# Build groups
Write-Info "Creating lab groups ..."
Ensure-LabGroups -Groups $groupList -RootOuName $labRootOuName -DomainDn $domainDn -Credential $cred
  
# Build users
$defaultPasswordPlain = "CyberLAB-is-Great!2025"
$defaultPassword = ConvertTo-SecureString $defaultPasswordPlain -AsPlainText -Force
  
Write-Info "Creating lab users and baseline group memberships ..."
Ensure-LabUsers -Users $users -RootOuName $labRootOuName -DomainDn $domainDn -DnsRoot $dnsRoot -DefaultPassword $defaultPassword -Credential $cred
  
# Misconfig overlay
if ($profileConfig.MisconfigIds -and $profileConfig.MisconfigIds.Count -gt 0) {
    Apply-Misconfigurations -ProfileConfig $profileConfig -Credential $cred
} else {
    Write-Info "Profile has no misconfig IDs; environment stays as secure baseline."
}
  
# Summary
Show-LabSummary -LabRootOuName $labRootOuName -ProfileConfig $profileConfig
 
  
 

