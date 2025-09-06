<#
.SYNOPSIS
Idempotent server join script: configure basic networking, enable management, rename and join domain.

.DESCRIPTION
Run this inside a new Windows Server VM (e.g. Server01, Server02, Storage01) as Administrator.
The script is idempotent for the common operations: it will skip steps that are already applied.

.PARAMETER NewName
Desired computer name. If omitted, the current computer name is used.

.PARAMETER DomainFqdn
The Active Directory domain to join (default: winlab.com).

.PARAMETER DomainAdminUser
Account to use when joining the domain (default: WINLAB\Administrator).

.PARAMETER StaticIP
Optional static IPv4 address to assign. If omitted, the script won't change IPs.

.EXAMPLE
.
  .\server-join.ps1 -NewName Server01 -StaticIP 192.168.50.10

#>

param(
  [string]$NewName = $env:COMPUTERNAME,
  [string]$DomainFqdn = 'winlab.com',
  [string]$DomainAdminUser = 'WINLAB\Administrator',
  [string]$StaticIP = '',
  [int]$PrefixLength = 24,
  [string]$Gateway = '192.168.50.1',
  [string]$DnsServers = ''
)

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
  Write-Error 'This script must be run as Administrator.'; return
}

Write-Host "[server-join] Starting on $env:COMPUTERNAME -> target name '$NewName'"

$restartRequired = $false

try {
  # 1) Optional: set static IP if provided
  if ($StaticIP -and $StaticIP.Trim() -ne '') {
    $iface = Get-NetAdapter | Where-Object Status -eq 'Up' | Select-Object -First 1 -ExpandProperty Name
    if (-not $iface) { Write-Warning '[server-join] No active network adapter found.' } else {
      $hasIp = Get-NetIPAddress -InterfaceAlias $iface -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -eq $StaticIP }
      if (-not $hasIp) {
        Write-Host "[server-join] Assigning static IP $StaticIP/$PrefixLength to $iface..."
        # Remove existing IPv4 addresses with same prefix length to avoid duplicates
        Get-NetIPAddress -InterfaceAlias $iface -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.PrefixLength -eq $PrefixLength } | ForEach-Object { Remove-NetIPAddress -InputObject $_ -Confirm:$false -ErrorAction SilentlyContinue }
        New-NetIPAddress -InterfaceAlias $iface -IPAddress $StaticIP -PrefixLength $PrefixLength -DefaultGateway $Gateway | Out-Null
        if ($DnsServers -and $DnsServers.Trim() -ne '') { Set-DnsClientServerAddress -InterfaceAlias $iface -ServerAddresses ($DnsServers -split ',') | Out-Null }
      } else { Write-Host "[server-join] Static IP $StaticIP already assigned on $iface." }
    }
  }

  # 2) Set network profile to Private
  $ifaceName = Get-NetAdapter | Where-Object Status -eq 'Up' | Select-Object -First 1 -ExpandProperty Name
  if ($ifaceName) {
    $connProfile = Get-NetConnectionProfile -InterfaceAlias $ifaceName -ErrorAction SilentlyContinue
    if ($connProfile.NetworkCategory -ne 'Private') {
      Write-Host "[server-join] Setting network profile to Private on $ifaceName..."
      Set-NetConnectionProfile -InterfaceAlias $ifaceName -NetworkCategory Private | Out-Null
    } else { Write-Host "[server-join] Network profile already Private on $ifaceName." }
  }

  # 3) Allow ping and Remote Desktop, File and Printer Sharing
  Write-Host '[server-join] Enabling ICMP, Remote Desktop and File and Printer Sharing firewall rules...'
  Set-NetFirewallRule -Name FPS-ICMP4-ERQ-In -Profile Private -Enabled True -ErrorAction SilentlyContinue
  Set-NetFirewallRule -Name FPS-ICMP6-ERQ-In -Profile Private -Enabled True -ErrorAction SilentlyContinue
  Enable-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue
  Enable-NetFirewallRule -DisplayGroup 'File and Printer Sharing' -ErrorAction SilentlyContinue

  # 4) Enable PSRemoting
  Write-Host '[server-join] Enabling PowerShell Remoting (WinRM)...'
  Enable-PSRemoting -Force -ErrorAction SilentlyContinue

  # 5) Rename computer if needed
  if ($NewName -and ($NewName -ne $env:COMPUTERNAME)) {
    Write-Host "[server-join] Renaming computer from $env:COMPUTERNAME to $NewName..."
    Rename-Computer -NewName $NewName -Force -ErrorAction Stop
    $restartRequired = $true
  } else { Write-Host '[server-join] Computer name already matches desired name.' }

  # 6) Join domain if not already a member
  $wmi = Get-WmiObject -Class Win32_ComputerSystem
  if (-not $wmi.PartOfDomain) {
    Write-Host "[server-join] Computer not in a domain. Joining $DomainFqdn..."
    $cred = Get-Credential -UserName $DomainAdminUser -Message 'Enter domain admin credentials to join the domain'
    Add-Computer -DomainName $DomainFqdn -Credential $cred -Force -ErrorAction Stop
    $restartRequired = $true
  } else { Write-Host "[server-join] Already joined to domain: $($wmi.Domain)" }

} catch {
  Write-Error "[server-join] Error: $($_.Exception.Message)"
  throw
}

if ($restartRequired) {
  Write-Host '[server-join] Restart required. Restarting now...'
  Restart-Computer -Force
} else { Write-Host '[server-join] Completed. No restart required.' }
