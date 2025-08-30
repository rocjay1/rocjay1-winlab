# WinLab Home Lab

A compact guide and scripts to spin up a Windows Hyper‑V home lab with working networking and sane defaults. Use this repo to quickly create internal (NAT) or external (bridged) virtual networks and stand up Windows Server evaluation VMs.

---

## Contents

- `Build_1.md`: Step‑by‑step setup for switches, VM creation, ISO mounting, networking, and fixes.
- `README.md`: High‑level overview, quick start, and pointers.

---

## Prerequisites

- Windows 10/11 Pro/Enterprise or Windows Server with Hyper‑V available.
- Admin PowerShell session.
- Hyper‑V feature enabled (reboot required):

```powershell
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All
```

- Windows Server ISO available (e.g., `C:\ISOs\WindowsServer2022.iso`).

---

## Quick Start

1. Create an Internal virtual switch and NAT:

```powershell
New-VMSwitch -Name "LabInternalSwitch" -SwitchType Internal
New-NetIPAddress -InterfaceAlias "vEthernet (LabInternalSwitch)" -IPAddress 192.168.50.1 -PrefixLength 24
New-NetNat -Name LabNAT -InternalIPInterfaceAddressPrefix 192.168.50.0/24
```

2. Create a Generation 2 VM and attach to the switch:

```powershell
New-VM -Name "WS2022-Lab" -Generation 2 -MemoryStartupBytes 4GB -SwitchName "LabInternalSwitch" -NewVHDPath "C:\VMs\WS2022.vhdx" -NewVHDSizeBytes 60GB
```

3. Mount the ISO and set boot order:

```powershell
Add-VMDvdDrive -VMName "WS2022-Lab" -Path "C:\ISOs\WindowsServer2022.iso"
$fw = Get-VMFirmware -VMName "WS2022-Lab"
Set-VMFirmware -VMName "WS2022-Lab" -FirstBootDevice $fw.BootOrder[2]
```

4. Inside the VM, configure IP (if using Internal + NAT):

```powershell
New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress 192.168.50.10 -PrefixLength 24 -DefaultGateway 192.168.50.1
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 8.8.8.8
```

For detailed steps and GUI alternatives, see `Build_1.md`.

---

## Networking Options

- Internal + NAT: Isolated lab with internet egress via host NAT.
- External (bridged): VMs appear directly on your LAN.

---

## Troubleshooting

- If DVD boot doesn’t trigger: set boot order to DVD first, then tap the space bar on startup to catch the boot prompt.
- Enable ICMP ping between VMs:

```powershell
Enable-NetFirewallRule -Name FPS-ICMP4-ERQ-In
```

---

## Notes

- Commands assume default names; adjust switch/paths as needed.
- Most commands require an elevated PowerShell.
