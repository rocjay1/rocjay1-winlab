# Hyper-V Home Lab Build Guide

This guide covers building a Hyper‑V home lab with Windows Server evaluation VMs, NAT networking, and a two‑DC Active Directory domain (`winlab.com`).

## Table of Contents

- [Hyper-V Home Lab Build Guide](#hyper-v-home-lab-build-guide)
  - [Table of Contents](#table-of-contents)
  - [Prerequisites](#prerequisites)
  - [Conventions](#conventions)
  - [Phase 1 — Hyper-V Infrastructure](#phase-1--hyper-v-infrastructure)
    - [1. Create a virtual switch](#1-create-a-virtual-switch)
      - [Internal switch (lab subnet + NAT)](#internal-switch-lab-subnet--nat)
    - [2. Create the domain controller VMs](#2-create-the-domain-controller-vms)
    - [3. Attach ISO and fix boot order](#3-attach-iso-and-fix-boot-order)
    - [4. VM networking config](#4-vm-networking-config)
    - [5. Rename and restart VMs](#5-rename-and-restart-vms)
    - [6. Enable basic connectivity and remote management](#6-enable-basic-connectivity-and-remote-management)
  - [Phase 2 — Active Directory and DNS deployment](#phase-2--active-directory-and-dns-deployment)
    - [0. Variables](#0-variables)
    - [1. DC01 setup (forest root)](#1-dc01-setup-forest-root)
      - [Networking](#networking)
      - [Install roles](#install-roles)
      - [Create forest](#create-forest)
      - [Post-reboot: DNS configuration](#post-reboot-dns-configuration)
    - [3. DC02 setup (additional DC)](#3-dc02-setup-additional-dc)
      - [Networking](#networking-1)
      - [Install roles](#install-roles-1)
      - [Promote as domain controller](#promote-as-domain-controller)
      - [Finalize DNS clients](#finalize-dns-clients)
    - [4. DNS and replication checks](#4-dns-and-replication-checks)
    - [5. Sites and subnets](#5-sites-and-subnets)
    - [6. Health and replication checks](#6-health-and-replication-checks)
    - [Post-install hardening](#post-install-hardening)
    - [Optional: DHCP and client join](#optional-dhcp-and-client-join)
    - [Optional: NAT port mapping](#optional-nat-port-mapping)
    - [Optional: backup](#optional-backup)
  - [End state](#end-state)

---

## Prerequisites

- Windows 11/Server host with Hyper‑V enabled and hardware virtualization (VT‑x/AMD‑V) on.
- PowerShell running as Administrator on the host.
- Folders exist: `C:\ProgramData\Microsoft\Windows\Virtual Hard Disks` and `C:\ProgramData\Microsoft\Windows\ISOs`; Windows Server ISO at `C:\ProgramData\Microsoft\Windows\ISOs\WindowsServer2025.iso`.
- Sufficient disk space (≈ 150 GB free) and RAM (≥ 16 GB recommended).
- Internet access (for evaluation ISOs, updates, and optional NTP).

## Conventions

- “Host (PowerShell)” means run on the Hyper‑V host. “Inside DC01/DC02 (PowerShell)” means run inside that VM.

> **Why these settings?** This guide favors clarity over defaults: the Internal switch keeps lab traffic isolated; NAT on the host provides internet; static IPs guarantee predictable DC addresses; and DNS on DCs enables AD features (SRV/NS records, secure dynamic updates).

---

## Phase 1 — Hyper-V Infrastructure

### 1. Create a virtual switch

#### Internal switch (lab subnet + NAT)

Host (PowerShell):

```powershell
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All -NoRestart
# Note: a reboot is typically required after enabling Hyper-V.

# Create a new virtual switch in Hyper-V.
# An "Internal" switch connects VMs to each other AND to the host (via a host vEthernet NIC).
# It does NOT connect to the external LAN unless you add routing/NAT on the host.
New-VMSwitch -Name "LabInternalSwitch" -SwitchType Internal

# The host now has a new NIC: vEthernet (LabInternalSwitch).
# Assign the host an IP on the lab subnet. This will be used as the VMs' default gateway
# IF (and only if) we configure NAT on the host.
New-NetIPAddress -InterfaceAlias "vEthernet (LabInternalSwitch)" `
                 -IPAddress 192.168.50.1 -PrefixLength 24

# Enable NAT so VMs in 192.168.50.0/24 can reach the internet via the host's external NIC.
# The host (IP 192.168.50.1) effectively becomes the default gateway for that subnet.
# Note: only one NAT can exist per internal prefix; ensure no duplicate NATs for 192.168.50.0/24.
New-NetNat -Name LabNAT -InternalIPInterfaceAddressPrefix 192.168.50.0/24
```

---

### 2. Create the domain controller VMs

Provision **two VMs**: `DC01` and `DC02`.

Host (PowerShell):

```powershell
# Create DC01
New-VM -Name "DC01" -Generation 2 -MemoryStartupBytes 4GB `
       -SwitchName "LabInternalSwitch" -NewVHDPath "C:\ProgramData\Microsoft\Windows\Virtual Hard Disks\DC01.vhdx" -NewVHDSizeBytes 60GB

# Create DC02
New-VM -Name "DC02" -Generation 2 -MemoryStartupBytes 4GB `
       -SwitchName "LabInternalSwitch" -NewVHDPath "C:\ProgramData\Microsoft\Windows\Virtual Hard Disks\DC02.vhdx" -NewVHDSizeBytes 60GB
```

---

### 3. Attach ISO and fix boot order

Host (PowerShell):

```powershell
Add-VMDvdDrive -VMName "DC01" -Path "C:\ProgramData\Microsoft\Windows\ISOs\WindowsServer2025.iso"
Add-VMDvdDrive -VMName "DC02" -Path "C:\ProgramData\Microsoft\Windows\ISOs\WindowsServer2025.iso"

# Prefer selecting the DVD device explicitly
Set-VMFirmware -VMName "DC01" -FirstBootDevice (Get-VMDvdDrive -VMName "DC01")
Set-VMFirmware -VMName "DC02" -FirstBootDevice (Get-VMDvdDrive -VMName "DC02")
```

> Note: On first boot, press Space when prompted to boot from DVD.

---

### 4. VM networking config

Assign static IPs and gateway inside each VM. DNS will be configured in Phase 2.

> **DNS on VMs**: don’t point DCs at public DNS (e.g., 8.8.8.8). During promotion, a DC must resolve AD SRV records locally; we set DC01 to use itself, and DC02 to use DC01 until it’s promoted.

Inside DC01 (PowerShell):

```powershell
New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress 192.168.50.2 -PrefixLength 24 -DefaultGateway 192.168.50.1
```

Inside DC02 (PowerShell):

```powershell
New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress 192.168.50.3 -PrefixLength 24 -DefaultGateway 192.168.50.1
```

---

### 5. Rename and restart VMs

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

### 6. Enable basic connectivity and remote management

Inside DC01 and DC02 (PowerShell):

```powershell
# Set profile to Private so discovery/sharing rules can apply
Set-NetConnectionProfile -InterfaceAlias "Ethernet" -NetworkCategory Private

# Allow ICMP echo (ping)
Set-NetFirewallRule -Name FPS-ICMP4-ERQ-In -Profile Private -Enabled True
Set-NetFirewallRule -Name FPS-ICMP6-ERQ-In -Profile Private -Enabled True

# Enable Remote Desktop
Enable-NetFirewallRule -DisplayGroup 'Remote Desktop'
# Allow RDP logons (terminal services toggle)
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 0

# Enable PowerShell Remoting (WinRM HTTP 5985)
Enable-PSRemoting -Force

# Enable File and Printer Sharing (SMB, etc.)
Enable-NetFirewallRule -DisplayGroup 'File and Printer Sharing'
```

---

## Phase 2 — Active Directory and DNS deployment

### 0. Variables

Inside DC01 and DC02 (PowerShell):

```powershell
$DomainFqdn  = "winlab.com"
$NetbiosName = "WINLAB"
$SubnetCIDR  = "192.168.50.0/24"

$DC1   = "DC01"
$DC2   = "DC02"
$DC1IP = "192.168.50.2"
$DC2IP = "192.168.50.3"

$PrefixLength  = 24
$Gateway       = "192.168.50.1"
$DnsForwarders = @("1.1.1.1","8.8.8.8")

$Interface = (Get-NetAdapter | Where-Object Status -eq Up | Select-Object -First 1 -ExpandProperty Name)
```

> **Forwarders**: these are upstream public resolvers for unknown names; they belong on the **DNS server** (zones forward out), not on the DC NIC’s DNS client list.

---

### 1. DC01 setup (forest root)

#### Networking

Inside DC01 (PowerShell):

```powershell
Set-DnsClientServerAddress -InterfaceAlias $Interface -ServerAddresses $DC1IP
```

> **Self-first DNS**: DC01 points to itself so Netlogon can publish SRV records in its own DNS and clients can find it during promotion.

#### Install roles

Inside DC01 (PowerShell):

```powershell
Install-WindowsFeature AD-Domain-Services, DNS -IncludeManagementTools
```

#### Create forest

Inside DC01 (PowerShell):

```powershell
$Dsrm = Read-Host "Enter DSRM password" -AsSecureString
Install-ADDSForest -DomainName $DomainFqdn -DomainNetbiosName $NetbiosName -InstallDNS -SafeModeAdministratorPassword $Dsrm
```

#### Post-reboot: DNS configuration

Inside DC01 (PowerShell):

```powershell
# Make sure the zones are forest-scoped
Set-DnsServerPrimaryZone -Name $DomainFqdn -ReplicationScope Forest -DynamicUpdate Secure  # secure updates + forest-wide visibility
Set-DnsServerPrimaryZone -Name "_msdcs.$DomainFqdn" -ReplicationScope Forest -DynamicUpdate Secure  # forest-wide SRV + GUID records

# Make sure DC01 advertises its SRV records
# Verify SRV (service locator) records so DCs/clients can find LDAP/Kerberos
Resolve-DnsName -Type SRV _ldap._tcp.dc._msdcs.winlab.com
Restart-Service netlogon
ipconfig /registerdns
nltest /dsregdns

# Add reverse lookup zone for virtual network
# Forward lookup zone was automatically created with forest
# Reverse zone enables PTR lookups and scavenging; optional but recommended
Add-DnsServerPrimaryZone -NetworkId $SubnetCIDR -ReplicationScope Forest

Add-DnsServerForwarder -IPAddress $DnsForwarders

# Enable scavenging
Set-DnsServerScavenging -ScavengingState $true -RefreshInterval (New-TimeSpan -Days 7) `
  -NoRefreshInterval (New-TimeSpan -Days 7) -ScavengingInterval (New-TimeSpan -Days 7)

# Enable zone-level aging for forward zone
Set-DnsServerZoneAging -Name $DomainFqdn -Aging $true -NoRefreshInterval (New-TimeSpan -Days 7) `
  -RefreshInterval (New-TimeSpan -Days 7)

# Resolve the reverse zone name created for 192.168.50.0/24 and enable aging
$Octets = $SubnetCIDR -split '\.'
$Octets = $Octets[0..($Octets.Length-2)]
$OctetsReversed = foreach ($i in 0..($Octets.Length-1)) { $Octets[($Octets.Length-1) - $i] }
$Prefix = $OctetsReversed -join '.'

$RevZone = (Get-DnsServerZone | Where-Object { $_.IsReverseLookupZone -and $_.ZoneName -like "$Prefix.in-addr.arpa" } | Select-Object -ExpandProperty ZoneName)
If ($RevZone) {
  Set-DnsServerZoneAging -Name $RevZone -Aging $true -NoRefreshInterval (New-TimeSpan -Days 7) -RefreshInterval (New-TimeSpan -Days 7)
}
```

> **What these do**: `-ReplicationScope Forest` makes zones replicate to all DNS servers in the forest; `-DynamicUpdate Secure` lets only authenticated machines update their A/PTR/SRV records (prevents spoofing). The `_msdcs` zone holds forest-wide **SRV** and **DC GUID CNAME** records used by clients and DC replication.

Verify:

```powershell
Resolve-DnsName $DC1
dcdiag /test:dns /v
```

---

### 3. DC02 setup (additional DC)

#### Networking

Inside DC02 (PowerShell):

```powershell
Set-DnsClientServerAddress -InterfaceAlias $Interface -ServerAddresses $DC1IP
```

> **Before promotion**: DC02 queries DC01 for `_msdcs` SRV records; after promotion we’ll switch DC02 to self-first.

#### Install roles

Inside DC02 (PowerShell):

```powershell
Install-WindowsFeature AD-Domain-Services, DNS -IncludeManagementTools
```

#### Promote as domain controller

Inside DC02 (PowerShell):

```powershell
$Cred  = Get-Credential
$Dsrm2 = Read-Host "Enter DSRM password for DC02" -AsSecureString
Install-ADDSDomainController -DomainName $DomainFqdn -Credential $Cred -InstallDNS -SafeModeAdministratorPassword $Dsrm2

# After the reboot, re-register SRV records on DC02
# Confirm DC02 now appears in SRV answers
Resolve-DnsName -Type SRV _ldap._tcp.dc._msdcs.winlab.com
Restart-Service netlogon
ipconfig /registerdns
nltest /dsregdns
```

#### Finalize DNS clients

Inside DC01 (PowerShell):

```powershell
Set-DnsClientServerAddress -InterfaceAlias $Interface -ServerAddresses @($DC1IP,$DC2IP)
```

Inside DC02 (PowerShell):

```powershell
Set-DnsClientServerAddress -InterfaceAlias $Interface -ServerAddresses @($DC2IP,$DC1IP)
```

> **DNS order**: each DC should list **itself first, partner second**. This avoids a single point of failure if one DC is down.

---

### 4. DNS and replication checks

Run these after promoting DC02 and before configuring Sites/Subnets to ensure healthy multi-DC DNS and replication.

Inside DC01 or DC02 (PowerShell): Verify NS records include both DCs; add missing NS if needed.

```powershell
# Inspect NS records
Get-DnsServerResourceRecord -ZoneName $DomainFqdn -RRType NS
Get-DnsServerResourceRecord -ZoneName "_msdcs.$DomainFqdn" -RRType NS

# Add DC02 as NS if absent
Add-DnsServerResourceRecord -ZoneName $DomainFqdn -NS -Name "@" -NameServer "dc02.$DomainFqdn"
Add-DnsServerResourceRecord -ZoneName "_msdcs.$DomainFqdn" -NS -Name "@" -NameServer "dc02.$DomainFqdn"
```

> **NS records**: identify which DNS servers are *authoritative* for the zone. Ensure both DC01 and DC02 are listed for `winlab.com` and `_msdcs.winlab.com`.

Inside DC01 and DC02 (PowerShell): Ensure DNS client order is self first, partner second.

```powershell
# On DC01
Set-DnsClientServerAddress -InterfaceAlias $Interface -ServerAddresses @($DC1IP,$DC2IP)

# On DC02
Set-DnsClientServerAddress -InterfaceAlias $Interface -ServerAddresses @($DC2IP,$DC1IP)
```

Inside DC01 and DC02 (PowerShell): Re-register Netlogon/DNS SRV records.

```powershell
Restart-Service netlogon
ipconfig /registerdns
nltest /dsregdns
```

> **Netlogon refresh kit**: restart Netlogon + re-register A/PTR/SRV to fix missing/old records after promotion.

Inside DC01 and DC02 (PowerShell): Confirm the network profile is DomainAuthenticated; if not, fix DNS and reboot.

```powershell
Get-NetConnectionProfile | Select-Object Name,NetworkCategory,DomainAuthenticationKind
# If not DomainAuthenticated, verify DNS, then:
Restart-Computer
```

> **NLA state**: on healthy DCs, `DomainAuthenticationKind` should show `DomainAuthenticated`. If it stays `None`, recheck DNS/SRV and restart `nlasvc`.

---

### 5. Sites and subnets

Inside DC01 or DC02 (PowerShell):

```powershell
New-ADReplicationSite "HQ"
New-ADReplicationSubnet -Name $SubnetCIDR -Site "HQ"
Move-ADDirectoryServer -Identity $DC1 -Site "HQ"
Move-ADDirectoryServer -Identity $DC2 -Site "HQ"
```

---

### 6. Health and replication checks

> **Replication quick tests**: DC discovery, summary health, and per-partition inbound neighbors.

Inside DC01 or DC02 (PowerShell):

```powershell
nltest /dsgetdc:$DomainFqdn
repadmin /replsummary
repadmin /showrepl
```

---

### Post-install hardening

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

> **Why disable Hyper‑V time sync on the PDC?** The PDC should be the time source for the forest; Hyper‑V time sync can fight w32time and cause drift.

- Updates: From each DC, run `sconfig` and install all updates, then reboot.

---

### Optional: DHCP and client join

DHCP on DC01 (or use your router and set options 003/006/015 accordingly).

Inside DC01 (PowerShell):

```powershell
Install-WindowsFeature DHCP -IncludeManagementTools
Add-DhcpServerInDC -DnsName "DC01.$DomainFqdn" -IpAddress $DC1IP
Add-DhcpServerv4Scope -Name "Lab" -StartRange 192.168.50.50 -EndRange 192.168.50.200 -SubnetMask 255.255.255.0 -State Active
Set-DhcpServerv4OptionValue -ScopeId 192.168.50.0 -Router $Gateway -DnsServer $DC1IP,$DC2IP -DnsDomain $DomainFqdn
```

> **DHCP options**: 003 = default gateway, 006 = DNS servers, 015 = DNS suffix. Point clients at the DCs for DNS so they can find SRV records.

Join a Windows client.

On the client (PowerShell as Administrator):

```powershell
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses $DC1IP,$DC2IP
Add-Computer -DomainName $DomainFqdn -Credential "$NetbiosName\Administrator" -Restart
```

### Optional: NAT port mapping

Expose RDP from the host to lab VMs via the NAT (use distinct ports):

Host (PowerShell):

```powershell
Add-NetNatStaticMapping -NatName "LabNAT" -Protocol TCP -ExternalIPAddress 0.0.0.0 -ExternalPort 53389 -InternalIPAddress $DC1IP -InternalPort 3389
Add-NetNatStaticMapping -NatName "LabNAT" -Protocol TCP -ExternalIPAddress 0.0.0.0 -ExternalPort 53390 -InternalIPAddress $DC2IP -InternalPort 3389
```

> Security note: Limit exposure to your LAN only (bind ExternalIPAddress to your LAN IP, not 0.0.0.0) and consider host/guest firewall rules.

### Optional: backup

Install Windows Server Backup and take regular System State backups of DCs.

Inside each DC (PowerShell):

```powershell
Install-WindowsFeature Windows-Server-Backup
# Example: system state backup to E: (external disk or share mapped drive)
wbadmin start systemstatebackup -backuptarget:E: -quiet
```

## End state

- Hyper-V host with **Internal NAT subnet (192.168.50.0/24)**.
- Two VMs provisioned (`DC01`, `DC02`) running Windows Server Eval.
- AD DS + DNS installed for `winlab.com` domain.
- Reverse zone, secure updates, scavenging enabled.
- Both DCs in **HQ Site**, replication verified.
- Clients configured to use DC01/DC02 for DNS and authentication.

---

> **If something feels off**: check `_msdcs` SRV records, NS records, and DNS client order on both DCs; 90% of AD lab issues trace back to these three.
