<#
.SYNOPSIS
Idempotent Host runbook for Hyper-V lab: create switch, NAT, and VMs.

.NOTES
- Run this on the Hyper-V host in an elevated PowerShell session.
- This script is idempotent: it will skip steps that are already complete.
#>

param(
  [string] $SwitchName = 'LabInternalSwitch',
  [string] $NatName = 'LabNAT',
  [string] $NetworkPrefix = '192.168.50.0/24',
  [string] $Gateway = '192.168.50.1',
  [int] $PrefixLength = 24,
  [string] $IsoPath = 'C:\ProgramData\Microsoft\Windows\ISOs\WindowsServer2025.iso'
)

# Ensure running elevated
If (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
  Write-Error 'This script must be run as Administrator on the host.'
  return
}

Write-Host "[Host] Starting idempotent host runbook..."

# 1) Enable Hyper-V optional feature if not enabled
try {
  $hv = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -ErrorAction Stop
  if ($hv.State -ne 'Enabled') {
    Write-Host '[Host] Enabling Hyper-V feature...'
    Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All -NoRestart
    Write-Host '[Host] Hyper-V enabled. A host reboot may be required.'
  } else {
    Write-Host '[Host] Hyper-V already enabled.'
  }
} catch {
  Write-Warning "[Host] Could not query or enable Hyper-V: $($_.Exception.Message)"
}

# 2) Create Internal VMSwitch if missing
if (-not (Get-VMSwitch -Name $SwitchName -ErrorAction SilentlyContinue)) {
  Write-Host "[Host] Creating internal switch '$SwitchName'..."
  New-VMSwitch -Name $SwitchName -SwitchType Internal | Out-Null
} else { Write-Host "[Host] VMSwitch '$SwitchName' already exists." }

# 3) Ensure host vEthernet has the gateway IP
$vEthName = "vEthernet ($SwitchName)"
$existingIP = Get-NetIPAddress -InterfaceAlias $vEthName -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -eq $Gateway }
if (-not $existingIP) {
  Write-Host "[Host] Assigning $Gateway/$PrefixLength to '$vEthName'..."
  # Remove any existing IPs on this interface in the same family to avoid duplicates
  Get-NetIPAddress -InterfaceAlias $vEthName -ErrorAction SilentlyContinue | Where-Object { $_.PrefixLength -eq $PrefixLength } | ForEach-Object { Remove-NetIPAddress -InputObject $_ -Confirm:$false -ErrorAction SilentlyContinue }
  New-NetIPAddress -InterfaceAlias $vEthName -IPAddress $Gateway -PrefixLength $PrefixLength | Out-Null
} else { Write-Host "[Host] Interface '$vEthName' already has $Gateway." }

# 4) Create NAT if missing
if (-not (Get-NetNat -Name $NatName -ErrorAction SilentlyContinue)) {
  Write-Host "[Host] Creating NAT '$NatName' for $NetworkPrefix..."
  New-NetNat -Name $NatName -InternalIPInterfaceAddressPrefix $NetworkPrefix | Out-Null
} else { Write-Host "[Host] NAT '$NatName' already exists." }

# 5) Create VMs if missing (DC01 / DC02)
function Ensure-VMExists {
  param($Name, $VhdPath, $Memory = 4GB, $VhdSizeBytes = 60GB, $Switch = $SwitchName)
  if (Get-VM -Name $Name -ErrorAction SilentlyContinue) {
    Write-Host "[Host] VM '$Name' already exists."
    return
  }
  Write-Host "[Host] Creating VM '$Name'..."
  New-VM -Name $Name -Generation 2 -MemoryStartupBytes $Memory -SwitchName $Switch -NewVHDPath $VhdPath -NewVHDSizeBytes $VhdSizeBytes | Out-Null
}

Ensure-VMExists -Name 'DC01' -VhdPath 'C:\ProgramData\Microsoft\Windows\Virtual Hard Disks\DC01.vhdx'
Ensure-VMExists -Name 'DC02' -VhdPath 'C:\ProgramData\Microsoft\Windows\Virtual Hard Disks\DC02.vhdx'

# 6) Attach ISO and ensure firmware boot order
function Ensure-IsoAttached {
  param($VMName, $IsoPath)
  $dvd = Get-VMDvdDrive -VMName $VMName -ErrorAction SilentlyContinue
  if (-not $dvd) {
    Write-Host "[Host] Adding DVD drive and attaching ISO to $VMName..."
    Add-VMDvdDrive -VMName $VMName -Path $IsoPath | Out-Null
  } else {
    if ($dvd.Path -ne $IsoPath) {
      Write-Host "[Host] Updating DVD ISO for $VMName..."
      Set-VMDvdDrive -VMName $VMName -Path $IsoPath | Out-Null
    } else { Write-Host "[Host] ISO already attached to $VMName." }
  }
  # Ensure DVD is first boot device
  Set-VMFirmware -VMName $VMName -FirstBootDevice (Get-VMDvdDrive -VMName $VMName) | Out-Null
}

Ensure-IsoAttached -VMName 'DC01' -IsoPath $IsoPath
Ensure-IsoAttached -VMName 'DC02' -IsoPath $IsoPath

Write-Host '[Host] Host runbook finished.'
