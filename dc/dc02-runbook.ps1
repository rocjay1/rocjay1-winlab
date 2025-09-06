<#
.SYNOPSIS
Idempotent runbook for DC02 — install roles and promote as additional DC.

.NOTES
- Run inside the DC02 VM as Administrator.
- Interactive credentials required for promotion.
#>

param(
  [string] $DomainFqdn = 'winlab.com',
  [string] $DC1IP = '192.168.50.2',
  [string] $DC2IP = '192.168.50.3'
)

If (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
  Write-Error 'This script must be run as Administrator inside DC02.'
  return
}

Write-Host '[DC02] Starting DC02 runbook...'

# Determine primary interface
$Interface = (Get-NetAdapter | Where-Object Status -eq 'Up' | Select-Object -First 1 -ExpandProperty Name)
Write-Host "[DC02] Using network interface: $Interface"

# 1) Set static IP
try {
  $current = Get-NetIPAddress -InterfaceAlias $Interface -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -eq $DC2IP }
  if (-not $current) {
    Write-Host "[DC02] Assigning IP $DC2IP..."
    New-NetIPAddress -InterfaceAlias $Interface -IPAddress $DC2IP -PrefixLength 24 -DefaultGateway '192.168.50.1' | Out-Null
  } else { Write-Host "[DC02] IP $DC2IP already assigned." }
} catch { Write-Warning "[DC02] IP assignment failed: $($_.Exception.Message)" }

# 2) Point DNS to DC01 prior to promotion
try {
  $dns = Get-DnsClientServerAddress -InterfaceAlias $Interface -ErrorAction SilentlyContinue
  if ($dns.ServerAddresses -ne $DC1IP) {
    Write-Host '[DC02] Setting DNS server to DC01 for promotion.'
    Set-DnsClientServerAddress -InterfaceAlias $Interface -ServerAddresses $DC1IP | Out-Null
  } else { Write-Host '[DC02] DNS already set to DC01.' }
} catch { Write-Warning "[DC02] DNS set failed: $($_.Exception.Message)" }

# 3) Install AD DS and DNS roles if not present
if (-not (Get-WindowsFeature AD-Domain-Services).Installed) {
  Write-Host '[DC02] Installing AD-Domain-Services and DNS features...'
  Install-WindowsFeature AD-Domain-Services, DNS -IncludeManagementTools | Out-Null
} else { Write-Host '[DC02] AD-Domain-Services already installed.' }

# 4) Promote as additional DC if not already
try {
  $isDC = (Get-ADDomainController -ErrorAction SilentlyContinue | Where-Object { $_.HostName -eq $env:COMPUTERNAME })
  if (-not $isDC) {
    Write-Host '[DC02] Promoting to additional domain controller...'
    $Cred = Get-Credential -Message 'Enter domain admin credentials for promotion'
    $Dsrm = Read-Host 'Enter DSRM password for DC02' -AsSecureString
    Install-ADDSDomainController -DomainName $DomainFqdn -Credential $Cred -InstallDNS -SafeModeAdministratorPassword $Dsrm -Force
    Write-Host '[DC02] Promotion initiated. This may reboot the server.'
  } else { Write-Host '[DC02] This server is already a domain controller.' }
} catch { Write-Warning "[DC02] Promotion failed or check failed: $($_.Exception.Message)" }

Write-Host '[DC02] DC02 runbook finished.'
