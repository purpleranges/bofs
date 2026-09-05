# bofs

A collection of Beacon Object Files for Active Directory and credential-access operations on Windows.

Detailed writeups for each BOF are published at [purpleranges.com](https://purpleranges.com).

## Installation

Prerequisites (mingw-w64 cross-compiler):

```
# Debian / Ubuntu / Kali
apt install g++-mingw-w64-x86-64-posix gcc-mingw-w64-x86-64-posix mingw-w64-tools

# Arch
pacman -Syu mingw-w64-gcc
```

## Build

```bash
git clone https://github.com/purpleranges/bofs
cd bofs
make
```

## Load in Adaptix

Load all modules in the AdaptixC2 client: **Main menu** → **Extensions** → **Script manager** → **Context menu** → **Load new** and select `bofs.axs` at the repo root. Every command from every module registers automatically.

The AxScript uses `ax.script_dir()` with relative paths, so the directory structure must stay intact.

## Modules

### ADDS-BOF

Active Directory Domain Services primitives operating over LDAP / LDAPS.

### Creds-BOF

Credential access primitives operating via local WinAPI.

## Available Commands

| Command | Usage | Notes |
| --- | --- | --- |
| `groupmod` | `groupmod <dc> <group_dn> <member_dn> add\|remove` | Add or remove a DN from a group's `member` attribute over LDAP 389. Idempotent-safe. |
| `gmsa-authorize` | `gmsa-authorize <dc> <gmsa_dn> set\|clear [<sid>]` | Write or clear the SD on `msDS-GroupMSAMembership` for gMSA password authorization. LDAP 389. |
| `gmsa-readpwd` | `gmsa-readpwd <dc> <gmsa_name> <search_base_dn>` | Reads `msDS-ManagedPassword` blob via LDAPS and returns NT hash (rc4_hmac). LDAPS 636. |
| `regsave` | `regsave`, `download <path>`, `regsave clean <sec> <sys>` | Save SECURITY + SYSTEM registry hives via WinAPI (no cmd.exe). Requires SYSTEM (SeBackupPrivilege). |

## System Support

Built and tested on Windows 11 and Windows Server 2025.

## Credits

`beacon.h` is vendored verbatim from [Cobalt-Strike/bof_template](https://github.com/Cobalt-Strike/bof_template) under the Apache License 2.0.

All BOFs in this repository were developed and used during the scenarios published at [purpleranges.com](https://purpleranges.com).
