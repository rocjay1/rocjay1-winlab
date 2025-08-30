# Hyper-V Home Lab Build Guide

This guide covers building a Hyper‑V home lab with Windows Server evaluation VMs, NAT networking, and a two‑DC Active Directory domain (`winlab.com`).

## Table of Contents

- [Hyper-V Home Lab Build Guide](#hyper-v-home-lab-build-guide)
  - [Table of Contents](#table-of-contents)
  - [Prerequisites](#prerequisites)
  - [Conventions](#conventions)
  - [Phase 1 — Hyper-V Infrastructure](#phase-1--hyper-v-infrastructure)
    - [1. Create a Virtual Switch](#1-create-a-virtual-switch)
      - [Internal Switch (lab subnet + NAT)](#internal-switch-lab-subnet--nat)
      - [Optional: External Switch + VM NICs](#optional-external-switch--vm-nics)
    - [2. Create the Domain Controller VMs](#2-create-the-domain-controller-vms)
    - [3. Attach ISO and Fix Boot Order](#3-attach-iso-and-fix-boot-order)
    - [4. VM Networking Config](#4-vm-networking-config)
    - [5. Rename and Restart VMs](#5-rename-and-restart-vms)
    - [6. Enable Inter-VM Ping](#6-enable-inter-vm-ping)
    - [Phase 1 Network Diagram](#phase-1-network-diagram)
  - [Phase 2 — Active Directory + DNS Deployment](#phase-2--active-directory--dns-deployment)
    - [0. Variables](#0-variables)
    - [1. DC01 Setup (Forest Root)](#1-dc01-setup-forest-root)
      - [Networking](#networking)
      - [Install Roles](#install-roles)
      - [Create Forest](#create-forest)
    - [2. DC01 DNS Post-Config](#2-dc01-dns-post-config)
    - [3. DC02 Setup (Additional DC)](#3-dc02-setup-additional-dc)
      - [Networking](#networking-1)
      - [Install Roles](#install-roles-1)
      - [Promote as DC](#promote-as-dc)
      - [Finalize DNS Clients](#finalize-dns-clients)
    - [4. Sites and Subnets](#4-sites-and-subnets)
    - [5. Health and Replication Checks](#5-health-and-replication-checks)
    - [Post-Install Hardening](#post-install-hardening)
    - [Phase 2 Domain Diagram](#phase-2-domain-diagram)
    - [Optional: DHCP + Client Join](#optional-dhcp--client-join)
    - [Optional: NAT Port Mapping](#optional-nat-port-mapping)
    - [Optional: Backup](#optional-backup)
  - [End State](#end-state)

---

## Prerequisites

- Windows 11/Server host with Hyper‑V enabled and hardware virtualization (VT‑x/AMD‑V) on.
- PowerShell running as Administrator on the host.
- Folders exist: `C:\VMs` and `C:\ISOs`; Windows Server ISO at `C:\ISOs\WindowsServer2022.iso`.
- Sufficient disk space (≈ 150 GB free) and RAM (≥ 16 GB recommended).
- Internet access (for evaluation ISOs, updates, and optional NTP).

## Conventions

- “Host (PowerShell)” means run on the Hyper‑V host. “Inside DC01/DC02 (PowerShell)” means run inside that VM.
- Network interface alias in VMs may vary (e.g., `Ethernet`, `Ethernet 2`). Adjust `-InterfaceAlias` accordingly.

---

## Phase 1 — Hyper-V Infrastructure

### 1. Create a Virtual Switch

#### Internal Switch (lab subnet + NAT)

Host (PowerShell):

```powershell
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All -NoRestart
New-VMSwitch -Name "LabInternalSwitch" -SwitchType Internal
New-NetIPAddress -InterfaceAlias "vEthernet (LabInternalSwitch)" `
                 -IPAddress 192.168.50.1 -PrefixLength 24
New-NetNat -Name LabNAT -InternalIPInterfaceAddressPrefix 192.168.50.0/24
```

#### Optional: External Switch + VM NICs

Host (PowerShell):

```powershell
New-VMSwitch -Name "ExternalSwitch" -NetAdapterName "Ethernet" -AllowManagementOS $true

# Optionally add a second NIC on each VM bridged to LAN
Add-VMNetworkAdapter -VMName "DC01" -SwitchName "ExternalSwitch" -Name "LAN"
Add-VMNetworkAdapter -VMName "DC02" -SwitchName "ExternalSwitch" -Name "LAN"
```

---

### 2. Create the Domain Controller VMs

Provision **two VMs**: `DC01` and `DC02`.

Host (PowerShell):

```powershell
# Create DC01
New-VM -Name "DC01" -Generation 2 -MemoryStartupBytes 4GB `
       -SwitchName "LabInternalSwitch" -NewVHDPath "C:\VMs\DC01.vhdx" -NewVHDSizeBytes 60GB

# Create DC02
New-VM -Name "DC02" -Generation 2 -MemoryStartupBytes 4GB `
       -SwitchName "LabInternalSwitch" -NewVHDPath "C:\VMs\DC02.vhdx" -NewVHDSizeBytes 60GB
```

---

### 3. Attach ISO and Fix Boot Order

Host (PowerShell):

```powershell
Add-VMDvdDrive -VMName "DC01" -Path "C:\ISOs\WindowsServer2022.iso"
Add-VMDvdDrive -VMName "DC02" -Path "C:\ISOs\WindowsServer2022.iso"

# Prefer selecting the DVD device explicitly
Set-VMFirmware -VMName "DC01" -FirstBootDevice (Get-VMDvdDrive -VMName "DC01")
Set-VMFirmware -VMName "DC02" -FirstBootDevice (Get-VMDvdDrive -VMName "DC02")
```

> Note: On first boot, press Space when prompted to boot from DVD.

---

### 4. VM Networking Config

Assign IPs inside the VMs (to be consistent with Phase 2):

- DC01 → `192.168.50.2/24`
- DC02 → `192.168.50.3/24`
- Gateway → `192.168.50.1`

Example (inside `DC01`):

Inside DC01 (PowerShell):

```powershell
New-NetIPAddress -InterfaceAlias "Ethernet" `
                 -IPAddress 192.168.50.2 -PrefixLength 24 -DefaultGateway 192.168.50.1
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 8.8.8.8
```

Repeat for `DC02` with `.3`.

---

### 5. Rename and Restart VMs

Rename the guest OS names to match `DC01`/`DC02` before AD promotion.

Inside DC01 (PowerShell):

```powershell
Rename-Computer -NewName "DC01" -Restart
```

Inside DC02 (PowerShell):

```powershell
Rename-Computer -NewName "DC02" -Restart
```

---

### 6. Enable Inter-VM Ping

On both DCs:

Inside DC01 and DC02 (PowerShell):

```powershell
Enable-NetFirewallRule -Name FPS-ICMP4-ERQ-In
Set-NetConnectionProfile -InterfaceAlias "Ethernet" -NetworkCategory Private
```

---

### Phase 1 Network Diagram

```text
          ┌───────────────────────────────┐
          │        Host (Win11)           │
          │ vEthernet (LabInternalSwitch) |
          │   IP: 192.168.50.1 (NAT)      │
          └─────────────┬─────────────────┘
                        │
       ┌────────────────┼────────────────┐
       │                                 │
┌───────────────┐               ┌───────────────┐
│ DC01          │               │ DC02          │
│ 192.168.50.2  │               │ 192.168.50.3  │
│ GW: .1        │               │ GW: .1        │
└───────────────┘               └───────────────┘
```

---

## Phase 2 — Active Directory + DNS Deployment

### 0. Variables

Inside DC01 and DC02 (PowerShell):

```powershell
$DomainFqdn   = "winlab.com"
$NetbiosName  = "WINLAB"
$SubnetCIDR   = "192.168.50.0/24"

$DC1          = "DC01"
$DC2          = "DC02"
$DC1IP        = "192.168.50.2"
$DC2IP        = "192.168.50.3"

$PrefixLength = 24
$Gateway      = "192.168.50.1"
$DnsForwarders = @("1.1.1.1","8.8.8.8")

$Interface    = (Get-NetAdapter | Where-Object Status -eq Up |
                 Select-Object -First 1 -ExpandProperty Name)
```

---

### 1. DC01 Setup (Forest Root)

#### Networking

Inside DC01 (PowerShell):

```powershell
New-NetIPAddress -InterfaceAlias $Interface -IPAddress $DC1IP -PrefixLength $PrefixLength -DefaultGateway $Gateway
Set-DnsClientServerAddress -InterfaceAlias $Interface -ServerAddresses $DC1IP
```

#### Install Roles

Inside DC01 (PowerShell):

```powershell
Install-WindowsFeature AD-Domain-Services, DNS -IncludeManagementTools
```

#### Create Forest

Inside DC01 (PowerShell):

```powershell
$Dsrm = Read-Host "Enter DSRM password" -AsSecureString
Install-ADDSForest -DomainName $DomainFqdn -DomainNetbiosName $NetbiosName `
                   -InstallDNS -SafeModeAdministratorPassword $Dsrm
```

> Note: Reboot and log in as `WINLAB\Administrator`.

---

### 2. DC01 DNS Post-Config

Inside DC01 (PowerShell):

```powershell
Add-DnsServerPrimaryZone -NetworkId $SubnetCIDR -ReplicationScope Forest
Set-DnsServerPrimaryZone -Name $DomainFqdn -DynamicUpdate Secure
Add-DnsServerForwarder -IPAddress $DnsForwarders
Set-DnsServerScavenging -ScavengingState $true -RefreshInterval (New-TimeSpan -Days 7) `
  -NoRefreshInterval (New-TimeSpan -Days 7) -ScavengingInterval (New-TimeSpan -Days 7)

# Enable zone-level aging for forward and reverse zones
Set-DnsServerZoneAging -Name $DomainFqdn -Aging $true -NoRefreshInterval (New-TimeSpan -Days 7) `
  -RefreshInterval (New-TimeSpan -Days 7)

# Resolve the reverse zone name created for 192.168.50.0/24 and enable aging
$RevZone = (Get-DnsServerZone | Where-Object { $_.IsReverseLookupZone -and $_.ZoneName -like '*.in-addr.arpa' } |
  Select-Object -First 1 -ExpandProperty ZoneName)
If ($RevZone) {
  Set-DnsServerZoneAging -Name $RevZone -Aging $true -NoRefreshInterval (New-TimeSpan -Days 7) -RefreshInterval (New-TimeSpan -Days 7)
}
```

Verify:

Inside DC01 (PowerShell):

```powershell
ipconfig /registerdns
Resolve-DnsName $DC1
dcdiag /test:dns /v
```

---

### 3. DC02 Setup (Additional DC)

#### Networking

Inside DC02 (PowerShell):

```powershell
New-NetIPAddress -InterfaceAlias $Interface -IPAddress $DC2IP -PrefixLength $PrefixLength -DefaultGateway $Gateway
Set-DnsClientServerAddress -InterfaceAlias $Interface -ServerAddresses $DC1IP
```

#### Install Roles

Inside DC02 (PowerShell):

```powershell
Install-WindowsFeature AD-Domain-Services, DNS -IncludeManagementTools
```

#### Promote as DC

Inside DC02 (PowerShell):

```powershell
$Cred  = Get-Credential
$Dsrm2 = Read-Host "Enter DSRM password for DC02" -AsSecureString
Install-ADDSDomainController -DomainName $DomainFqdn -Credential $Cred `
                             -InstallDNS -SafeModeAdministratorPassword $Dsrm2
```

#### Finalize DNS Clients

Inside DC01 (PowerShell):

```powershell
Set-DnsClientServerAddress -InterfaceAlias $Interface -ServerAddresses @($DC1IP,$DC2IP)
```

Inside DC02 (PowerShell):

```powershell
Set-DnsClientServerAddress -InterfaceAlias $Interface -ServerAddresses @($DC2IP,$DC1IP)
```

---

### 4. Sites and Subnets

Inside DC01 or DC02 (PowerShell):

```powershell
New-ADReplicationSite "HQ"
New-ADReplicationSubnet -Name $SubnetCIDR -Site "HQ"
Move-ADDirectoryServer -Identity $DC1 -Site "HQ"
Move-ADDirectoryServer -Identity $DC2 -Site "HQ"
```

---

### 5. Health and Replication Checks

Inside DC01 or DC02 (PowerShell):

```powershell
nltest /dsgetdc:$DomainFqdn
repadmin /replsummary
repadmin /showrepl
```

---

### Post-Install Hardening

- Time service (PDC emulator): Configure the forest PDC to use external NTP. By default, the first DC (DC01) is the PDC.

Inside DC01 (PowerShell):

```powershell
# Verify PDC
(Get-ADDomain).PDCEmulator

# Configure NTP servers and mark PDC reliable
w32tm /config /manualpeerlist:"time.windows.com,0x8 1.pool.ntp.org,0x8" /syncfromflags:MANUAL /update
w32tm /config /reliable:yes
Restart-Service w32time
w32tm /resync /force
```

Host (PowerShell):

```powershell
# Disable Hyper-V time sync integration on the PDC VM only
Disable-VMIntegrationService -VMName "DC01" -Name "Time Synchronization"
```

- Remote management: Enable RDP and PowerShell remoting on both DCs.

Inside DC01 and DC02 (PowerShell):

```powershell
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 0
Enable-NetFirewallRule -DisplayGroup 'Remote Desktop'
Enable-PSRemoting -Force
```

- Updates: From each DC, run `sconfig` and install all updates, then reboot.

### Phase 2 Domain Diagram

```text
                         ┌────────────────────────┐
                         │    winlab.com          │
                         │    NetBIOS: WINLAB     │
                         └────────────┬───────────┘
                                      │
       ┌──────────────────────────────┼───────────────────────────┐
       │                              │                           │
 ┌───────────────┐             ┌───────────────┐        ┌───────────────┐
 │ DC01          │             │ DC02          │        │   Clients     │
 │ 192.168.50.2  │◄─replicate─►│ 192.168.50.3  │        │ DHCP / Static │
 │ AD DS + DNS   │             │ AD DS + DNS   │        │ Use DC01/DC02 │
 └───────────────┘             └───────────────┘        └───────────────┘
```

---

### Optional: DHCP + Client Join

DHCP on DC01 (or use your router and set options 003/006/015 accordingly).

Inside DC01 (PowerShell):

```powershell
Install-WindowsFeature DHCP -IncludeManagementTools
Add-DhcpServerInDC -DnsName "DC01.$DomainFqdn" -IpAddress $DC1IP
Add-DhcpServerv4Scope -Name "Lab" -StartRange 192.168.50.50 -EndRange 192.168.50.200 -SubnetMask 255.255.255.0 -State Active
Set-DhcpServerv4OptionValue -ScopeId 192.168.50.0 -Router $Gateway -DnsServer $DC1IP,$DC2IP -DnsDomain $DomainFqdn
```

Join a Windows client:

On the client (PowerShell as Administrator):

```powershell
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses $DC1IP,$DC2IP
Add-Computer -DomainName $DomainFqdn -Credential "$NetbiosName\Administrator" -Restart
```

### Optional: NAT Port Mapping

Expose RDP from the host to lab VMs via the NAT (use distinct ports):

Host (PowerShell):

```powershell
Add-NetNatStaticMapping -NatName "LabNAT" -Protocol TCP -ExternalIPAddress 0.0.0.0 -ExternalPort 53389 -InternalIPAddress $DC1IP -InternalPort 3389
Add-NetNatStaticMapping -NatName "LabNAT" -Protocol TCP -ExternalIPAddress 0.0.0.0 -ExternalPort 53390 -InternalIPAddress $DC2IP -InternalPort 3389
```

> Security note: Limit exposure to your LAN only and consider firewall rules.

### Optional: Backup

Install Windows Server Backup and take regular System State backups of DCs.

Inside each DC (PowerShell):

```powershell
Install-WindowsFeature Windows-Server-Backup
# Example: system state backup to E: (external disk or share mapped drive)
wbadmin start systemstatebackup -backuptarget:E: -quiet
```

## End State

- Hyper-V host with **Internal NAT subnet (192.168.50.0/24)**.
- Two VMs provisioned (`DC01`, `DC02`) running Windows Server Eval.
- AD DS + DNS installed for `winlab.com` domain.
- Reverse zone, secure updates, scavenging enabled.
- Both DCs in **HQ Site**, replication verified.
- Clients configured to use DC01/DC02 for DNS and authentication.
