# Hyper-V Home Lab Build Guide

Build a Hyper-V home lab with Windows Server evaluation VMs, NAT networking, and a two-DC Active Directory domain (`winlab.com`).

> **At-a-glance IP plan**
>
> | Item    | Value              |
> |:--------|:-------------------|
> | Subnet  | `192.168.50.0/24`  |
> | Gateway | `192.168.50.1` (host vEthernet) |
> | DC01    | `192.168.50.2`     |
> | DC02    | `192.168.50.3`     |

---

## Table of Contents

- [Hyper-V Home Lab Build Guide](#hyper-v-home-lab-build-guide)
  - [Table of Contents](#table-of-contents)
  - [Prerequisites](#prerequisites)
  - [Conventions](#conventions)
  - [Phase 1 — Hyper-V Infrastructure](#phase-1--hyper-v-infrastructure)
    - [1. Create a virtual switch](#1-create-a-virtual-switch)
    - [2. Create the domain controller VMs](#2-create-the-domain-controller-vms)
    - [4. VM networking config](#4-vm-networking-config)
    - [5. Rename and restart VMs](#5-rename-and-restart-vms)
    - [6. Enable basic connectivity and remote management](#6-enable-basic-connectivity-and-remote-management)
  - [Phase 2 — Active Directory and DNS deployment](#phase-2--active-directory-and-dns-deployment)
    - [0. Variables](#0-variables)
    - [1. DC01 setup (forest root)](#1-dc01-setup-forest-root)
      - [Networking](#networking)
      - [Install roles](#install-roles)
      - [Create forest](#create-forest)
      - [DNS configuration](#dns-configuration)
    - [3. DC02 setup (additional DC)](#3-dc02-setup-additional-dc)
      - [Networking](#networking-1)
      - [Install roles](#install-roles-1)
      - [Promote as domain controller](#promote-as-domain-controller)
    - [4. Finalize DNS](#4-finalize-dns)
      - [DC DNS client settings](#dc-dns-client-settings)
      - [Confirm domain records](#confirm-domain-records)
    - [5. Sites and subnets](#5-sites-and-subnets)
    - [6. Health and replication checks](#6-health-and-replication-checks)
    - [Post-install hardening](#post-install-hardening)
    - [Optional: DHCP and client join](#optional-dhcp-and-client-join)
      - [Client join (PowerShell as Administrator)](#client-join-powershell-as-administrator)
    - [Optional: NAT port mapping](#optional-nat-port-mapping)
    - [Optional: backup](#optional-backup)
  - [End state](#end-state)
  - [Troubleshooting quick hits](#troubleshooting-quick-hits)

---

## Prerequisites

- [ ] Windows 11/Server host with **Hyper-V** enabled and hardware virtualization (VT-x/AMD-V).
- [ ] **PowerShell as Administrator** on the host.
- [ ] Folders exist:  
  `C:\ProgramData\Microsoft\Windows\Virtual Hard Disks`  
  `C:\ProgramData\Microsoft\Windows\ISOs`  
  Server ISO at `C:\ProgramData\Microsoft\Windows\ISOs\WindowsServer2025.iso`.
- [ ] ≈ **150 GB free** disk and **≥16 GB RAM** recommended.
- [ ] Internet access (for eval ISOs/updates/optional NTP).

## Conventions

> **Run on:**  
> **Host (PowerShell)** = Hyper-V host.  
> **Inside DC01/DC02 (PowerShell)** = commands run inside that VM.

---

## Phase 1 — Hyper-V Infrastructure

### 1. Create a virtual switch

> **Run on:** Host (PowerShell)

<details><summary><strong>Show commands</strong></summary>

```powershell
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All -NoRestart
# Reboot is typically required after enabling Hyper-V.

# Internal switch: VMs talk to each other and the host (vEthernet), not the external LAN.
New-VMSwitch -Name "LabInternalSwitch" -SwitchType Internal

# Give the host vEthernet NIC a gateway IP on the lab subnet.
New-NetIPAddress -InterfaceAlias "vEthernet (LabInternalSwitch)" -IPAddress 192.168.50.1 -PrefixLength 24

# NAT so 192.168.50.0/24 can reach the internet via the host.
New-NetNat -Name LabNAT -InternalIPInterfaceAddressPrefix 192.168.50.0/24
```

</details>

---

### 2. Create the domain controller VMs

> **Run on:** Host (PowerShell)

<details><summary><strong>Show commands</strong></summary>

```powershell
# DC01
New-VM -Name "DC01" -Generation 2 -MemoryStartupBytes 4GB `
       -SwitchName "LabInternalSwitch" `
       -NewVHDPath "C:\ProgramData\Microsoft\Windows\Virtual Hard Disks\DC01.vhdx" `
       -NewVHDSizeBytes 60GB

# DC02
New-VM -Name "DC02" -Generation 2 -MemoryStartupBytes 4GB `
       -SwitchName "LabInternalSwitch" `
       -NewVHDPath "C:\ProgramData\Microsoft\Windows\Virtual Hard Disks\DC02.vhdx" `
       -NewVHDSizeBytes 60GB

# Attach ISO and fix boot order
Add-VMDvdDrive -VMName "DC01" -Path "C:\ProgramData\Microsoft\Windows\ISOs\WindowsServer2025.iso"
Add-VMDvdDrive -VMName "DC02" -Path "C:\ProgramData\Microsoft\Windows\ISOs\WindowsServer2025.iso"

# Prefer explicit DVD first-boot device
Set-VMFirmware -VMName "DC01" -FirstBootDevice (Get-VMDvdDrive -VMName "DC01")
Set-VMFirmware -VMName "DC02" -FirstBootDevice (Get-VMDvdDrive -VMName "DC02")
```

</details>

> **Note:** On first boot, press **Space** when prompted to boot from DVD.

---

### 4. VM networking config

> **Important:** Don’t point DCs at public DNS during promotion. DC01 uses **itself**; DC02 uses **DC01** until promoted.

> **Run on:** DC01 (PowerShell)

<details><summary><strong>Show commands</strong></summary>

```powershell
New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress 192.168.50.2 -PrefixLength 24 -DefaultGateway 192.168.50.1
```

</details>

> **Run on:** DC02 (PowerShell)

<details><summary><strong>Show commands</strong></summary>

```powershell
New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress 192.168.50.3 -PrefixLength 24 -DefaultGateway 192.168.50.1
```

</details>

---

### 5. Rename and restart VMs

> **Run on:** DC01 (PowerShell)

<details><summary><strong>Show commands</strong></summary>

```powershell
Rename-Computer -NewName "DC01" -Restart
```

</details>

> **Run on:** DC01 (PowerShell)

<details><summary><strong>Show commands</strong></summary>

```powershell
Rename-Computer -NewName "DC02" -Restart
```

</details>

---

### 6. Enable basic connectivity and remote management

> **Run on:** DC01 **and** DC02 (PowerShell)

<details><summary><strong>Show commands</strong></summary>

```powershell
# Set network profile to Private.
Set-NetConnectionProfile -InterfaceAlias "Ethernet" -NetworkCategory Private

# Allow ping.
Set-NetFirewallRule -Name FPS-ICMP4-ERQ-In -Profile Private -Enabled True
Set-NetFirewallRule -Name FPS-ICMP6-ERQ-In -Profile Private -Enabled True

# Enable Remote Desktop.
Enable-NetFirewallRule -DisplayGroup 'Remote Desktop'
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 0

# PowerShell Remoting (WinRM 5985).
Enable-PSRemoting -Force

# File and Printer Sharing.
Enable-NetFirewallRule -DisplayGroup 'File and Printer Sharing'
```

</details>

---

## Phase 2 — Active Directory and DNS deployment

### 0. Variables

> **Run on:** DC01 **and** DC02 (PowerShell)

<details><summary><strong>Show commands</strong></summary>

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

</details>

---

### 1. DC01 setup (forest root)

#### Networking

> **Run on:** DC01 (PowerShell)

<details><summary><strong>Show commands</strong></summary>

```powershell
Set-DnsClientServerAddress -InterfaceAlias $Interface -ServerAddresses $DC1IP
```

</details>

#### Install roles

> **Run on:** DC01 (PowerShell)

<details><summary><strong>Show commands</strong></summary>

```powershell
Install-WindowsFeature AD-Domain-Services, DNS -IncludeManagementTools
```

</details>

#### Create forest

> **Run on:** DC01 (PowerShell)

<details><summary><strong>Show commands</strong></summary>

```powershell
$Dsrm = Read-Host "Enter DSRM password" -AsSecureString
Install-ADDSForest -DomainName $DomainFqdn -DomainNetbiosName $NetbiosName -InstallDNS -SafeModeAdministratorPassword $Dsrm
```

</details>

#### DNS configuration

> **Run on:** DC01 (PowerShell)

<details><summary><strong>Show commands</strong></summary>

```powershell
# Forest-scoped primary zones + secure dynamic updates.
Set-DnsServerPrimaryZone -Name $DomainFqdn -ReplicationScope Forest -DynamicUpdate Secure
Set-DnsServerPrimaryZone -Name "_msdcs.$DomainFqdn" -ReplicationScope Forest -DynamicUpdate Secure

# Verify SRV records and force re-register if needed.
Resolve-DnsName -Type SRV _ldap._tcp.dc._msdcs.winlab.com
Restart-Service netlogon
ipconfig /registerdns
nltest /dsregdns

# Reverse zone for PTR lookups.
Add-DnsServerPrimaryZone -NetworkId $SubnetCIDR -ReplicationScope Forest

# Forwarders and scavenging.
Add-DnsServerForwarder -IPAddress $DnsForwarders
Set-DnsServerScavenging -ScavengingState $true `
  -RefreshInterval (New-TimeSpan -Days 7) `
  -NoRefreshInterval (New-TimeSpan -Days 7) `
  -ScavengingInterval (New-TimeSpan -Days 7)

# Zone-level aging for forward zone.
Set-DnsServerZoneAging -Name $DomainFqdn `
  -Aging $true `
  -NoRefreshInterval (New-TimeSpan -Days 7) `
  -RefreshInterval (New-TimeSpan -Days 7)

# Find reverse zone name and enable aging.
$Octets = $SubnetCIDR -split '\.'
$Octets = $Octets[0..($Octets.Length-2)]
$OctetsReversed = foreach ($i in 0..($Octets.Length-1)) { $Octets[($Octets.Length-1) - $i] }
$Prefix = $OctetsReversed -join '.'

$RevZone = (
  Get-DnsServerZone | 
  Where-Object { $_.IsReverseLookupZone -and $_.ZoneName -like "$Prefix.in-addr.arpa" } | 
  Select-Object -ExpandProperty ZoneName
)
If ($RevZone) {
  Set-DnsServerZoneAging -Name $RevZone `
    -Aging $true `
    -NoRefreshInterval (New-TimeSpan -Days 7) `
    -RefreshInterval (New-TimeSpan -Days 7)
}

# Verify results.
Resolve-DnsName $DC1
dcdiag /test:dns /v
```

</details>

> **Why:** `-ReplicationScope Forest` replicates to all AD-integrated DNS servers; `-DynamicUpdate Secure` restricts updates to authenticated machines. `_msdcs` stores forest-wide SRV/DC GUID CNAMEs.

---

### 3. DC02 setup (additional DC)

#### Networking

> **Run on:** DC02 (PowerShell)

<details><summary><strong>Show commands</strong></summary>

```powershell
Set-DnsClientServerAddress -InterfaceAlias $Interface -ServerAddresses $DC1IP
```

</details>

> **Note:** DC02 queries DC01 for `_msdcs` SRV records; after promotion we’ll set DC02 to **self-first**.

#### Install roles

> **Run on:** DC02 (PowerShell)

<details><summary><strong>Show commands</strong></summary>

```powershell
Install-WindowsFeature AD-Domain-Services, DNS -IncludeManagementTools
```

</details>

#### Promote as domain controller

> **Run on:** DC02 (PowerShell)

<details><summary><strong>Show commands</strong></summary>

```powershell
$Cred  = Get-Credential
$Dsrm2 = Read-Host "Enter DSRM password for DC02" -AsSecureString
Install-ADDSDomainController -DomainName $DomainFqdn -Credential $Cred -InstallDNS -SafeModeAdministratorPassword $Dsrm2

# Confirm DC02 now appears in SRV answers.
Resolve-DnsName -Type SRV _ldap._tcp.dc._msdcs.winlab.com
Restart-Service netlogon
ipconfig /registerdns
nltest /dsregdns
```

</details>

---

### 4. Finalize DNS

#### DC DNS client settings

> **Run on:** DC01 and DC02 (PowerShell)

<details><summary><strong>Show commands</strong></summary>

```powershell
# DC01: self first, partner second
Set-DnsClientServerAddress -InterfaceAlias $Interface -ServerAddresses @($DC1IP,$DC2IP)

# DC02: self first, partner second
Set-DnsClientServerAddress -InterfaceAlias $Interface -ServerAddresses @($DC2IP,$DC1IP)
```

</details>

> **DNS order:** Each DC lists **itself first, partner second** to avoid a single point of failure.

#### Confirm domain records

> **Goal:** Ensure both DCs are authoritative (NS records present), and A/PTR/SRV are fresh.

> **Run on:** DC01 (PowerShell)

<details><summary><strong>Show commands</strong></summary>

```powershell
# Inspect NS records.
Get-DnsServerResourceRecord -ZoneName $DomainFqdn -RRType NS
Get-DnsServerResourceRecord -ZoneName "_msdcs.$DomainFqdn" -RRType NS

# Add DC02 as NS if absent.
Add-DnsServerResourceRecord -ZoneName $DomainFqdn -NS -Name "@" -NameServer "dc02.$DomainFqdn"
Add-DnsServerResourceRecord -ZoneName "_msdcs.$DomainFqdn" -NS -Name "@" -NameServer "dc02.$DomainFqdn"

# Re-register Netlogon/DNS SRV if needed (run on both DCs).
Restart-Service netlogon
ipconfig /registerdns
nltest /dsregdns

# Confirm DomainAuthenticated profile; if not, fix DNS/SRV and reboot.
Get-NetConnectionProfile | Select-Object Name,NetworkCategory,DomainAuthenticationKind
# If needed:
Restart-Computer
```

</details>

---

### 5. Sites and subnets

> **Run on:** DC01 (PowerShell)

<details><summary><strong>Show commands</strong></summary>

```powershell
New-ADReplicationSite "HQ"
New-ADReplicationSubnet -Name $SubnetCIDR -Site "HQ"
Move-ADDirectoryServer -Identity $DC1 -Site "HQ"
Move-ADDirectoryServer -Identity $DC2 -Site "HQ"
```

</details>

---

### 6. Health and replication checks

> **Run on:** DC01 **and** DC02 (PowerShell)

<details><summary><strong>Show commands</strong></summary>

```powershell
nltest /dsgetdc:$DomainFqdn
repadmin /replsummary
repadmin /showrepl
```

</details>

---

### Post-install hardening

> **PDC time source:** First DC (DC01) is the PDC by default; make it authoritative for time and disable Hyper-V time sync on the **PDC VM only**.

> **Run on:** DC01 (PowerShell)

<details><summary><strong>Show commands</strong></summary>

```powershell
(Get-ADDomain).PDCEmulator

w32tm /config /manualpeerlist:"time.windows.com,0x8 1.pool.ntp.org,0x8" /syncfromflags:MANUAL /update
w32tm /config /reliable:yes
Restart-Service w32time
w32tm /resync /force
```

</details>

> **Run on:** Host (PowerShell)

<details><summary><strong>Show commands</strong></summary>

```powershell
Disable-VMIntegrationService -VMName "DC01" -Name "Time Synchronization"
```

</details>

> **Updates:** On each DC, run `sconfig`, install all updates, reboot.

---

### Optional: DHCP and client join

> **Run on:** DC01 (PowerShell)

<details><summary><strong>Show commands</strong></summary>

```powershell
Install-WindowsFeature DHCP -IncludeManagementTools
Add-DhcpServerInDC -DnsName "DC01.$DomainFqdn" -IpAddress $DC1IP
Add-DhcpServerv4Scope -Name "Lab" `
  -StartRange 192.168.50.50 `
  -EndRange 192.168.50.200 `
  -SubnetMask 255.255.255.0 `
  -State Active
Set-DhcpServerv4OptionValue -ScopeId 192.168.50.0 -Router $Gateway -DnsServer $DC1IP,$DC2IP -DnsDomain $DomainFqdn
```

</details>

> By default, domain-joined clients register their **A** record themselves, but **PTR** (reverse) is typically handled by **DHCP**. To ensure both A and PTR records exist even for non-domain or
legacy clients, configure DHCP to always perform dynamic updates and give it credentials for secure updates.

> **Run on:** DC01 (PowerShell)

<details><summary><strong>Show commands</strong></summary>

```powershell
# Server-wide (applies to all IPv4 scopes)
# Always dynamically update DNS records (A + PTR), remove stale records at lease expiry,
# and update for older/legacy clients that don't request it explicitly
Set-DhcpServerv4DnsSetting -DynamicUpdates Always `
  -DeleteDnsRROnLeaseExpiry $true `
  -UpdateDnsRRForOlderClients $true

# OR

# Per-scope (override or set on a single scope)
$ScopeId = "192.168.50.0"  # network ID of your scope
Set-DhcpServerv4DnsSetting -ScopeId $ScopeId -DynamicUpdates Always `
  -DeleteDnsRROnLeaseExpiry $true `
  -UpdateDnsRRForOlderClients $true

# Credentials for secure updates
# (Run in an elevated PowerShell on a DC)
New-ADUser -Name "dhcpdns" -SamAccountName "dhcpdns" -AccountPassword (Read-Host -AsSecureString "Password") -Enabled $true
# Optional but common in labs: prevent password expiry for this service account
Set-ADUser dhcpdns -PasswordNeverExpires $true

# (Run on the DHCP server) — store credentials for DNS updates
$cred = Get-Credential "WINLAB\dhcpdns"
Set-DhcpServerDnsCredential -Credential $cred

# Verify
Get-DhcpServerv4DnsSetting                    # server-wide settings
Get-DhcpServerv4DnsSetting -ScopeId $ScopeId  # per-scope (if set)
Get-DhcpServerDnsCredential                   # shows stored account used for updates
```

</details>

> **DHCP options:** 003 = gateway, 006 = DNS servers, 015 = DNS suffix. Point clients at **DCs** for DNS to find SRV records.

#### Client join (PowerShell as Administrator)

> **Run on:** Client (PowerShell as Administrator)

<details><summary><strong>Show commands</strong></summary>

```powershell
Add-Computer -DomainName $DomainFqdn -Credential "$NetbiosName\Administrator" -Restart

# Renew lease if needed:
ipconfig /release
ipconfig /renew
ipconfig /flushdns
ipconfig /registerdns  # refresh A from client side (PTR handled by DHCP)
```

</details>

---

### Optional: NAT port mapping

> **Run on:** Host (PowerShell)

<details><summary><strong>Show commands</strong></summary>

```powershell
Add-NetNatStaticMapping -NatName "LabNAT" `
  -Protocol TCP `
  -ExternalIPAddress 0.0.0.0 `
  -ExternalPort 53389 `
  -InternalIPAddress $DC1IP `
  -InternalPort 3389

Add-NetNatStaticMapping -NatName "LabNAT" `
  -Protocol TCP `
  -ExternalIPAddress 0.0.0.0 `
  -ExternalPort 53389 `
  -InternalIPAddress $DC2IP `
  -InternalPort 3389
```

</details>

> **Security:** Prefer binding `ExternalIPAddress` to your **LAN IP** (not `0.0.0.0`), and tighten host/guest firewall rules.

---

### Optional: backup

> **Run on:** Inside each DC (PowerShell)

<details><summary><strong>Show commands</strong></summary>

```powershell
Install-WindowsFeature Windows-Server-Backup
# Example: system state backup to E: (external disk or mapped share)
wbadmin start systemstatebackup -backuptarget:E: -quiet
```

</details>

---

## End state

- Hyper-V host with **Internal NAT subnet** (`192.168.50.0/24`).
- Two VMs (`DC01`, `DC02`) running Windows Server Eval.
- AD DS + DNS for **`winlab.com`** deployed.
- Reverse zone, secure updates, scavenging enabled.
- Both DCs in **HQ Site**; replication verified.
- Clients use **DC01/DC02** for DNS and authentication.

---

## Troubleshooting quick hits

- Check `_msdcs` **SRV** records, **NS** records, and **DNS client order** on both DCs—most AD lab issues trace back here.
- If `DomainAuthenticationKind` ≠ `DomainAuthenticated`, fix DNS/SRV, restart `nlasvc`, and/or reboot.
- After promotion, **restart Netlogon** and **re-register DNS**:  
  `Restart-Service netlogon; ipconfig /registerdns; nltest /dsregdns`
