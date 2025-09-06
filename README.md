# Hyper-V Home Lab — Runbook quick start

This small README explains the per-machine, idempotent runbooks created from the original guide. Each script is written to be safe to re-run and includes checks to skip already-completed steps.

Scripts (paths relative to repo root)

- `host/hyperv-host-runbook.ps1` — run on the Hyper-V host (create switch, NAT, VMs, attach ISOs).
- `dc/dc01-runbook.ps1` — run inside the first domain controller VM (DC01): install AD DS/DNS, create forest, basic DNS config.
- `dc/dc02-runbook.ps1` — run inside the second domain controller VM (DC02): install roles and promote as additional DC.
- `servers/server-join.ps1` — generic idempotent server join script (set IP, firewall, PSRemoting, rename, domain join).
- `servers/server01-join.ps1`, `servers/server02-join.ps1`, `servers/storage01-join.ps1` — convenience wrappers that call `server-join.ps1` with per-host parameters.
- `client/client-join-runbook.ps1` — run on a Windows client to join the domain (checks membership first).

Note: `scripts/AddServer.ps1` has been refactored to point operators to the new `servers/` workflow; host-side VM creation examples remain in that file as guidance.

Recommended execution order

1. Prepare host: ensure the host has Hyper-V enabled, the required folders, and the server ISO present.
2. Run the host runbook on the Hyper-V host to create the internal switch, NAT, and the two DC VMs.
3. Boot/Install OS on each VM (use the attached ISO).
4. Create and prepare additional server VMs (Server01, Server02, Storage01) on the host as needed.
5. Inside DC01 (elevated): run the `dc01` runbook to install AD and create the forest. Follow the interactive DSRM prompt.
6. Inside DC02 (elevated): run the `dc02` runbook to promote it as an additional domain controller.
7. Inside each server VM (Server01, Server02, Storage01) run the matching wrapper from `servers/` to perform networking, enable management, rename, and join the domain.
8. Optionally run the `client` runbook on a client to join the domain.

Quick usage examples

Host (open an elevated PowerShell on the host)

```powershell
# From Windows PowerShell (run as Administrator)
Set-Location 'C:/Path/To/rocjay1-winlab'  # adjust path
./host/hyperv-host-runbook.ps1

# Or using PowerShell Core
# pwsh -NoProfile -ExecutionPolicy Bypass -File ./host/hyperv-host-runbook.ps1
```

DC01 (inside the VM, run as Administrator)

```powershell
# Copy or open the repository files in the VM, then run:
pwsh -NoProfile -ExecutionPolicy Bypass -File C:/Path/To/repo/dc/dc01-runbook.ps1

# The script prompts for the DSRM password and may reboot the VM.
```

DC02 (inside the VM, run as Administrator)

```powershell
# Ensure DC01 is reachable and DNS is pointed at DC01 before promotion.
pwsh -NoProfile -ExecutionPolicy Bypass -File C:/Path/To/repo/dc/dc02-runbook.ps1

# The script prompts for domain admin credentials and a DSRM password.
```

Server VMs (inside each server, run as Administrator)

```powershell
# Run the per-server wrapper from inside the VM (recommended):
# Example: Server01
pwsh -NoProfile -ExecutionPolicy Bypass -File C:/Path/To/repo/servers/server01-join.ps1

# Example: Server02
pwsh -NoProfile -ExecutionPolicy Bypass -File C:/Path/To/repo/servers/server02-join.ps1

# Example: Storage01
pwsh -NoProfile -ExecutionPolicy Bypass -File C:/Path/To/repo/servers/storage01-join.ps1

# Or run the generic join script with parameters:
# pwsh -NoProfile -ExecutionPolicy Bypass -File C:/Path/To/repo/servers/server-join.ps1 -NewName Server01 -StaticIP 192.168.50.11 -DnsServers '192.168.50.2,192.168.50.3'
```

Client (on a workstation, run as Administrator)

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File ./client/client-join-runbook.ps1
# or run interactively and provide domain admin credentials when prompted
```

Notes and prerequisites

- All scripts expect to be run in an elevated PowerShell (Administrator) session.
- Interactive prompts are intentionally preserved for passwords and credentials to avoid insecure credential storage.
- Scripts are idempotent for common operations (they perform existence checks before creating objects). They are meant as operator-friendly runbooks, not an unattended deployment pipeline.
- Adjust IPs, ISO path, and other parameters at the top of each script if your environment differs from `192.168.50.0/24` and the default names.
