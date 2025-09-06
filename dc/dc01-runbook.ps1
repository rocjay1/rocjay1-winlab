<#
.SYNOPSIS
Idempotent runbook for DC01 (forest root) — install roles, create forest, configure DNS.

.NOTES
- Run inside the DC01 VM as Administrator.
- Interactive prompts required for DSRM password and possibly reboots.
#>

param(
  [string] $DomainFqdn = 'winlab.com',
  [string] $NetbiosName = 'WINLAB',
  [string] $DC1IP = '192.168.50.2',
  [string] $DC2IP = '192.168.50.3'
)

If (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
  Write-Error 'This script must be run as Administrator inside DC01.'
  return
}

Write-Host '[DC01] Starting DC01 runbook...'

# Determine primary interface
$Interface = (Get-NetAdapter | Where-Object Status -eq 'Up' | Select-Object -First 1 -ExpandProperty Name)
Write-Host "[DC01] Using network interface: $Interface"

# 1) Set static IP (idempotent)
try {
  $current = Get-NetIPAddress -InterfaceAlias $Interface -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -eq $DC1IP }
  if (-not $current) {
    Write-Host "[DC01] Assigning IP $DC1IP..."
    New-NetIPAddress -InterfaceAlias $Interface -IPAddress $DC1IP -PrefixLength 24 -DefaultGateway '192.168.50.1' | Out-Null
  } else { Write-Host "[DC01] IP $DC1IP already assigned." }
} catch { Write-Warning "[DC01] IP assignment failed: $($_.Exception.Message)" }

# 2) Point DNS to self
try {
  $dns = Get-DnsClientServerAddress -InterfaceAlias $Interface -ErrorAction SilentlyContinue
  if ($dns.ServerAddresses -ne $DC1IP) {
    Write-Host '[DC01] Setting DNS server to self.'
    Set-DnsClientServerAddress -InterfaceAlias $Interface -ServerAddresses $DC1IP | Out-Null
  } else { Write-Host '[DC01] DNS already set to self.' }
} catch { Write-Warning "[DC01] DNS set failed: $($_.Exception.Message)" }

# 3) Install AD DS and DNS roles if not present
if (-not (Get-WindowsFeature AD-Domain-Services).Installed) {
  Write-Host '[DC01] Installing AD-Domain-Services and DNS features...'
  Install-WindowsFeature AD-Domain-Services, DNS -IncludeManagementTools | Out-Null
} else { Write-Host '[DC01] AD-Domain-Services already installed.' }

# 4) Create forest if it doesn't exist
try {
  $existing = Get-ADForest -ErrorAction SilentlyContinue
  if (-not $existing) {
    Write-Host '[DC01] No AD forest found. Creating forest...'
    $Dsrm = Read-Host 'Enter DSRM password' -AsSecureString
    Install-ADDSForest -DomainName $DomainFqdn -DomainNetbiosName $NetbiosName -InstallDNS -SafeModeAdministratorPassword $Dsrm -Force
    Write-Host '[DC01] Forest creation initiated. This may reboot the server.'
  } else {
    Write-Host "[DC01] Forest already exists: $($existing.Name)"
  }
} catch { Write-Warning "[DC01] Forest check/create failed: $($_.Exception.Message)" }

# 5) DNS configuration (zones, forwarders, scavenging)
try {
  if (Get-DnsServerZone -Name $DomainFqdn -ErrorAction SilentlyContinue) {
    Write-Host '[DC01] DNS forward zone already exists.'
  } else {
    Write-Host "[DC01] Creating DNS primary zone for $DomainFqdn..."
    Add-DnsServerPrimaryZone -Name $DomainFqdn -ReplicationScope Forest -DynamicUpdate Secure | Out-Null
  }

  if (-not (Get-DnsServerForwarder -ErrorAction SilentlyContinue)) {
    Write-Host '[DC01] Adding DNS forwarders...'
    Add-DnsServerForwarder -IPAddress '1.1.1.1','8.8.8.8' | Out-Null
  } else { Write-Host '[DC01] DNS forwarders appear configured.' }

  # Scavenging
  Set-DnsServerScavenging -ScavengingState $true -RefreshInterval (New-TimeSpan -Days 7) -NoRefreshInterval (New-TimeSpan -Days 7) -ScavengingInterval (New-TimeSpan -Days 7)
} catch { Write-Warning "[DC01] DNS config failed: $($_.Exception.Message)" }

Write-Host '[DC01] DC01 runbook finished.'
