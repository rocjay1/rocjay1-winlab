<#
.SYNOPSIS
Idempotent client join runbook — join a Windows client to the domain if not already joined.

.NOTES
- Run on the client machine in an elevated PowerShell session.
#>

param(
  [string] $DomainFqdn = 'winlab.com',
  [string] $DomainAdmin = 'WINLAB\\Administrator'
)

If (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
  Write-Error 'This script must be run as Administrator on the client.'
  return
}

Write-Host '[Client] Checking domain membership...'
try {
  $computerSystem = Get-WmiObject -Class Win32_ComputerSystem
  if ($computerSystem.PartOfDomain) {
    Write-Host "[Client] Already joined to domain: $($computerSystem.Domain)"
    return
  }
} catch { Write-Warning "[Client] Could not determine domain membership: $($_.Exception.Message)" }

# Prompt for credentials to join
$cred = Get-Credential -UserName $DomainAdmin -Message 'Enter domain admin credentials to join this computer to the domain'

Write-Host "[Client] Joining $env:COMPUTERNAME to $DomainFqdn..."
Add-Computer -DomainName $DomainFqdn -Credential $cred -Force -ErrorAction Stop
Write-Host '[Client] Join successful: restarting...'
Restart-Computer -Force
