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

## Networking Options

- Internal + NAT: Isolated lab with internet egress via host NAT.
- External (bridged): VMs appear directly on your LAN.

---

## Notes

- Commands assume default names; adjust switch/paths as needed.
- Most commands require an elevated PowerShell.
