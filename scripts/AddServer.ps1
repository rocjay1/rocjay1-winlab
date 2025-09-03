# New VM name
$name = 'Server01'

# Create the new VM in Hyper-V
# Run from host
New-VM -Name $name -Generation 2 -MemoryStartupBytes 4GB `
  -SwitchName "LabInternalSwitch" `
  -NewVHDPath "C:\ProgramData\Microsoft\Windows\Virtual Hard Disks\$name.vhdx" `
  -NewVHDSizeBytes 60GB

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
