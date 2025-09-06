# New VM name
$name = 'Server01'

# Create the new VM in Hyper-V
# Run from host
<#
This script previously contained inline steps to create a VM and configure it.
Those steps have been refactored into the new `servers/` folder as idempotent
join scripts. Use the wrappers under `servers/` inside the VM to finish join and
configuration tasks.

Examples:

On the host, create the VM (example):

  $name = 'Server01'
  New-VM -Name $name -Generation 2 -MemoryStartupBytes 4GB -SwitchName 'LabInternalSwitch' -NewVHDPath "C:\ProgramData\Microsoft\Windows\Virtual Hard Disks\$name.vhdx" -NewVHDSizeBytes 60GB
  Add-VMDvdDrive -VMName $name -Path 'C:\ProgramData\Microsoft\Windows\ISOs\WindowsServer2025.iso'
  Set-VMFirmware -VMName $name -FirstBootDevice (Get-VMDvdDrive -VMName $name)

Then, inside the VM (as Administrator) run the appropriate wrapper:

  # inside Server01 VM
  pwsh -NoProfile -ExecutionPolicy Bypass -File C:\Path\To\repo\servers\server01-join.ps1

  # inside Server02 VM
  pwsh -NoProfile -ExecutionPolicy Bypass -File C:\Path\To\repo\servers\server02-join.ps1

Or run the generic join script with parameters:

  pwsh -NoProfile -ExecutionPolicy Bypass -File C:\Path\To\repo\servers\server-join.ps1 -NewName Server01 -StaticIP 192.168.50.11 -DnsServers '192.168.50.2,192.168.50.3'

#>

Write-Host 'See servers/server-join.ps1 and wrappers in servers/ for the new workflow.'

Add-VMDvdDrive -VMName $name -Path "C:\ProgramData\Microsoft\Windows\ISOs\WindowsServer2025.iso"

Set-VMFirmware -VMName $name -FirstBootDevice (Get-VMDvdDrive -VMName $name)

# Enable basic connectivity and RDP
# Run from inside the VM
Set-NetConnectionProfile -InterfaceAlias "Ethernet" -NetworkCategory Private

Set-NetFirewallRule -Name FPS-ICMP4-ERQ-In -Profile Private -Enabled True
Set-NetFirewallRule -Name FPS-ICMP6-ERQ-In -Profile Private -Enabled True

Enable-NetFirewallRule -DisplayGroup 'Remote Desktop'
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 0

Enable-PSRemoting -Force

Enable-NetFirewallRule -DisplayGroup 'File and Printer Sharing'

# Rename the VM to match name in Hyper-V Manager
# Run from inside the VM
Rename-Computer -NewName $name -Restart

# Join to domain
# Run from inside the VM
Add-Computer -DomainName 'winlab.com' -Credential "WINLAB\Administrator" -Restart
