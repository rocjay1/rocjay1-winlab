# Hyper-V Home Lab Setup Guide

This guide documents the process of creating a Hyper-V home lab VM (Windows Server Eval) with working networking and boot troubleshooting fixes.

---

## Prerequisites

- Windows 10/11 Pro/Enterprise or Windows Server with Hyper‑V available.
- Admin PowerShell session for all commands below.
- Hyper‑V feature enabled (reboot required):

```powershell
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All
```

- Windows Server installation ISO available (e.g., `C:\ISOs\WindowsServer2022.iso`).
- Sufficient resources: ≥ 4 GB RAM and ~60 GB disk space per VM.

---

## Create a Virtual Switch

You have two main choices:

### Internal Switch (isolated lab + NAT for internet)

GUI:

 1. Open Hyper-V Manager → Virtual Switch Manager.
 2. Create Internal switch (e.g., LabInternalSwitch).

PowerShell:

```powershell
New-VMSwitch -Name "LabInternalSwitch" -SwitchType Internal
```

Assign host IP (gateway for lab subnet):

```powershell
New-NetIPAddress -InterfaceAlias "vEthernet (LabInternalSwitch)" `
                 -IPAddress 192.168.50.1 -PrefixLength 24
```

Enable NAT:

```powershell
New-NetNat -Name LabNAT -InternalIPInterfaceAddressPrefix 192.168.50.0/24
```

---

### External Switch (bridge to LAN)

GUI: Create External switch bound to host’s physical NIC.

PowerShell:

```powershell
New-VMSwitch -Name "ExternalSwitch" -NetAdapterName "Ethernet" -AllowManagementOS $true
```

---

## Create a New VM

GUI:

 1. New → Virtual Machine
 2. Generation 2 (UEFI) unless testing legacy OS.
 3. Assign RAM (≥ 4 GB for GUI edition).
 4. Create virtual disk (e.g., 60 GB).
 5. Attach NIC to LabInternalSwitch or ExternalSwitch.
 6. Do not specify ISO yet (workaround for boot failure).

PowerShell:

```powershell
New-VM -Name "WS2022-Lab" -Generation 2 -MemoryStartupBytes 4GB `
       -SwitchName "LabInternalSwitch" -NewVHDPath "C:\VMs\WS2022.vhdx" -NewVHDSizeBytes 60GB
```

---

## Mount ISO

Add DVD drive with ISO:

```powershell
Add-VMDvdDrive -VMName "WS2022-Lab" -Path "C:\ISOs\WindowsServer2022.iso"
```

Set boot order:

```powershell
$fw = Get-VMFirmware -VMName "WS2022-Lab"
Set-VMFirmware -VMName "WS2022-Lab" -FirstBootDevice $fw.BootOrder[2] # DVD first
```

---

## Fix Boot Failures

Steps that worked:

- Provision VM without ISO initially.
- Attach ISO later as DVD drive.
- Set boot order: DVD → Hard Drive → Network.
- Tap the space bar at VM startup to trigger CD/DVD boot prompt.

---

## Configure Networking

Inside VM (using Internal + NAT):

- Default gateway = host’s Internal switch IP (e.g., `192.168.50.1`).
- DNS = public (`8.8.8.8`) or custom.

PowerShell inside VM:

```powershell
New-NetIPAddress -InterfaceAlias "Ethernet" `
                 -IPAddress 192.168.50.10 -PrefixLength 24 -DefaultGateway 192.168.50.1
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 8.8.8.8
```

---

## Enable Inter-VM Ping

Windows Firewall blocks ICMP echo by default. Enable it:

```powershell
Enable-NetFirewallRule -Name FPS-ICMP4-ERQ-In
```

Or mark the NIC as Private:

```powershell
Set-NetConnectionProfile -InterfaceAlias "Ethernet" -NetworkCategory Private
```

---

## ASCII Network Diagram

Here’s what the setup looks like with an Internal switch + NAT:

```
          ┌────────────────────────────┐
          │        Host (Win11)        │
          │   Physical NIC: 192.168.1.50│───► Home LAN / Internet
          │                            │
          │ vEthernet (LabInternalSwitch)
          │   IP: 192.168.50.1         │
          └─────────────┬──────────────┘
                        │  NAT (LabNAT)
      ┌─────────────────┼───────────────────┐
      │                 │                   │
┌──────────────┐ ┌──────────────┐ ┌──────────────┐
│   VM1        │ │   VM2        │ │   VM3        │
│ IP: .10/24   │ │ IP: .11/24   │ │ IP: .12/24   │
│ GW: .1       │ │ GW: .1       │ │ GW: .1       │
└──────────────┘ └──────────────┘ └──────────────┘
```

---
