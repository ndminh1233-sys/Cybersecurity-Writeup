# Phase 3 — MITRE ATT&CK Simulation: Kerberoasting & AD Enumeration (Attack + Detection)

**Author:** me
**Environment:** Self-built Active Directory homelab + Kali attacker + Wazuh SIEM
**Focus:** Blue Team / SOC — detection engineering, not just exploitation
**Techniques covered:** T1558.003 (Kerberoasting), T1087.002 (Account Discovery: Domain Account)

---

## Overview

This phase simulates two post-foothold Active Directory attacks from a Kali box and attempts to **detect each one in a SIEM (Wazuh)**. The goal is not to compromise the domain — it is to answer the question a SOC analyst actually gets paid to answer: *when this attack runs, does my telemetry catch it, and can I write a reliable rule for it?*

The headline result is a detection-engineering finding: in a modern AES-default domain, **the "obvious" Kerberoasting signature (RC4 encryption) has a 100% miss rate** — proven by testing, not by reading. This forced a shift from signature-based to behavioural detection, which is the real lesson of the phase.

---

## Lab Environment

| Component | Detail |
|---|---|
| Domain | `******` |
| Domain Controller | `******` @ `***` (AD DS, DNS, Kerberos, LDAP) |
| Attacker | Kali Linux @ `****` (not domain-joined, same network) |
| SIEM | Wazuh 4.x on a dedicated Ubuntu server, agent on the DC |
| Foothold credential | `****` — low-privilege domain user recovered from an earlier password-spray phase (reset to a known lab password for continuity) |
| Target service account | `******` — a standard AD user running SQL Server, with an SPN registered |

---

## Background: the two account roles

These two accounts do different jobs, and conflating them is a common beginner mistake worth stating explicitly:

- **``** — the credential you attack *with*. A plain domain user. In Kerberos terms, the "member card" that lets you ask the KDC for things. No special privileges required.
- **``** — the account you attack. A normal AD user whose purpose is to be the login identity that the SQL Server software runs as. It is a target only because it has an **SPN** (Service Principal Name) registered, which is what makes it Kerberoastable.

Key Kerberos rule that the whole attack rests on: **any authenticated domain user can request a service ticket for any SPN.** The KDC gatekeeps *identity* (are you a valid user?), not *authorisation* (should you use this service?) — that decision is left to the service itself. This is normal and necessary behaviour that the attack abuses.

---

## Technique 1 — T1558.003 Kerberoasting

### What it is and why it works

Kerberoasting requests a service ticket for an SPN-bearing account, then cracks it offline. The service ticket is **encrypted with the service account's password hash**, so cracking the ticket yields the account's password. Because the cracking happens offline (on the attacker's machine), it generates **no failed logons and no lockouts** — the domain never sees the guessing. This is why weak, never-rotated service-account passwords are catastrophic.

It is an **escalation** technique, not initial access — it requires a foothold first.

### Attack execution

Run as the low-privilege `janed` foothold (not Administrator — using an admin account would defeat the point of the demo):

```bash
impacket-GetUserSPNs ******/janed:'<password>' -dc-ip ****** -request
```

The single command does **two jobs**:

1. Ask the DC *"list every account that has an SPN"* → the domain returns the service accounts (here: `svc_sql`). `svc_sql` is never typed into the command — the **domain supplies it**. In a real environment with dozens of service accounts, this is how you discover their names without prior knowledge.
2. `-request` → for each discovered SPN account, request its service ticket and dump the crackable hash.

Result: an RC4 ticket hash for `svc_sql`:

```
$krb5tgs$23$*svc_sql$...$MSSQLSvc/...*$<hex blob>
```

The `$23$` = encryption type 23 = **0x17 = RC4** (weak, crackable). Offline cracking would use:

```bash
hashcat -m 13100 hashes.txt wordlist.txt
```

The username is free (AD is a readable directory — account names are not secret); only the **password** requires the cracking effort.

### Building durable audit policy (GPO)

Kerberos ticket events must survive reboots, so audit policy was set via **GPO** rather than fragile `auditpol` commands:

- Created `Lab-Kerberos-Audit`
- Enabled **Success + Failure** on:
  - *Kerberos Service Ticket Operations* → Event ID **4769**
  - *Kerberos Authentication Service* → Event ID **4768**
- Linked to the **Domain Controllers OU** (DC-specific events, so it must apply to the DC)

**Why Success + Failure:** Failure catches attempts; Success catches tickets that were actually issued. Kerberoasting produces a *successful* ticket grant, so Success is essential here.

### Detection blocker: the 4769 / 1108 bug

After the attack, `4769` was confirmed **present locally** on the DC but **not reaching Wazuh**, while `4768` flowed fine.

Diagnosis chain:
1. Confirmed 4769 exists locally (`Get-WinEvent ... Id=4769`) → audit policy is working.
2. Confirmed Wazuh agent running and reconnected (fixed a stale keep-alive).
3. Found **Event ID 1108** firing immediately before the missing 4769s: *"The event logging service encountered an error while processing an incoming event..."*
4. Researched it: a documented, intermittent **Windows Event Log service bug** — not a misconfiguration on our end.

### Fix: the audit subcategory override

Windows has **two layered audit systems**: legacy "basic" categories (9 broad buckets) and modern "advanced" subcategories (~60 fine-grained, used by `auditpol` and our GPO). When both are configured, they can contradict each other, and **legacy category settings can silently override the advanced subcategory settings** — cancelling them out.

The tiebreaker is one Security Option:

```
GPO → Computer Configuration → Policies → Windows Settings
    → Security Settings → Local Policies → Security Options
      → "Audit: Force audit policy subcategory settings to override
         category settings (Windows Vista or later)"  →  ENABLED
```

```powershell
gpupdate /force
auditpol /get /category:*   # verify "Kerberos Service Ticket Operations" = Success and Failure
```

After enabling this and re-running the attack, **4769 flowed end-to-end into Wazuh.** Blocker closed.

> **Pattern worth noting:** this is the same "necessary but not sufficient — two independent gates" structure seen in Phase 1 (NLA disable vs. auditpol). Configuring the subcategory is necessary; the override policy is a second gate that must also be enabled or the subcategory config is correct-but-not-authoritative. Layered gates that must all align is a recurring theme in Windows auditing.

### Key finding: RC4 signature detection fails in an AES domain

With 4769 finally reaching the SIEM, the natural detection rule is *"alert on 4769 with RC4 (0x17) encryption"* — the classic Kerberoasting signature. Testing it produced a contradiction:

- **Attack side:** the cracked hash was `$23$` → **RC4**
- **Detection side:** **zero** 4769 events showed `0x17`. All logged `0x12` (**AES256**).

The ticket was RC4, but the DC logged no RC4 ticket. Root cause found by checking the account's encryption preference:

```powershell
Get-ADUser svc_sql -Properties msDS-SupportedEncryptionTypes |
  Format-List Name, msDS-SupportedEncryptionTypes
# → msDS-SupportedEncryptionTypes : (blank)
```

`msDS-SupportedEncryptionTypes` (ms = Microsoft, DS = Directory Services) defines which Kerberos ciphers an account accepts. When **blank**, the account falls back to the **DC default — AES** on a modern domain. So:

- `svc_sql` advertises no preference → DC issues and **logs** the service ticket as **AES (0x12)**
- Impacket still negotiates and extracts a crackable **RC4 (`$23$`)** blob on the request side

**Consequence:** the DC never issues or logs an RC4 service ticket. An RC4/0x17-based detection rule has a **100% miss rate** against an AES-default service account.

| Value of `msDS-SupportedEncryptionTypes` | Meaning |
|---|---|
| blank / 0 | DC default (AES on modern domains) |
| 4 | RC4 only |
| 24 | AES128 + AES256 |
| 28 | RC4 + AES128 + AES256 |

This is the most valuable finding of the phase: the "textbook" detection was **demonstrated to fail**, not assumed to work.

### The detection that actually works (behavioural)

Since cipher is unreliable, Kerberoasting detection must be **behavioural**:

> Alert on **one account requesting 4769 service tickets for an unusual number of distinct SPNs in a short time window** — regardless of encryption type.

Both `GetUserSPNs -request` and SharpHound sweep *all* SPNs in one burst, so volume + velocity from a single principal is the reliable signal. Supporting signals: a user account requesting a ticket for a service SPN it has no business touching, and 4769 activity correlated with LDAP enumeration (see Technique 2).

*(Status: behavioural rule designed, not yet implemented in Wazuh — see Open Items.)*

---

## Technique 2 — T1087.002 Account Discovery (BloodHound)

### What it is and why

BloodHound ingests Active Directory and turns it into a **graph of who-can-reach-what**, pre-computing privilege relationships (group nesting, ACLs, sessions) that no human could trace manually. The analyst's question: *does my foothold have an attack path to Tier Zero (Domain Admins / the domain / the DC)?*

### Collection: one root cause defeated every Linux tool

| Attempt | Tool | Result |
|---|---|---|
| 1 | `bloodhound-ce-python` | **Failed** — LDAP signing forces LDAPS; the ldap3 library cannot cleanly handle the DC's self-signed certificate |
| 2 | `nxc ldap ... --bloodhound` (NetExec) | **Failed** — missing internal `bloodhound` Python dependency (Kali packaging gap) |
| 3 | **SharpHound on the DC** | **Success** — 326 objects in ~12s |

**Root cause (the common thread):** the DC enforces **LDAP signing**, which forces collectors onto LDAPS, and the Linux (ldap3-based) tools choke on the DC's self-signed cert. This was not a series of unrelated bugs — it was one cause defeating every Linux collector. The accepted workaround is **SharpHound run natively on Windows**, which uses the OS's own Kerberos/LDAP stack and satisfies signing automatically.

Infrastructure notes worth recording:
- BloodHound CE UI is at `:8080`; Neo4j browser (`:7474`) is just the raw database console — a common point of confusion.
- `bloodhound` is deprecated → use `bloodhound-setup` / `bloodhound-start`.
- Neo4j on Kali does not register with systemd (own service manager) — a red herring during setup.
- Real startup fix: start Postgres via `systemctl start postgresql.service`, **and** URL-encode the special character in the Neo4j password inside `/etc/bhapi/bhapi.json` (found via `journalctl`).

### File transfer DC → Kali

```bash
# Kali — note the creds; anonymous SMB is blocked by default
impacket-smbserver share . -smb2support -user labuser -password <password>
```
```cmd
:: DC
net use \\ip\share /user:labuser <password>
copy *.zip \\ip\share
```

### Graph analysis results

Node inspection via the BloodHound info panel (Outbound Object Control = what a node can attack; Inbound = what can compromise it; Sessions = where credentials sit in memory):

- **`janed`** — no outbound object control, **no path to Domain Admins**. A clean low-privilege foothold.
- **`svc_sql`** — only SQL-server-level admin rights, **no AD outbound control, no escalation path**. Its privilege lives at the application layer (inside SQL Server), which AD — and therefore BloodHound — cannot see.
- All edges terminating at Domain Admins originate from **inherently privileged principals** (Administrators, Enterprise Admins, built-in Administrator) — i.e. the default plumbing, not an exploitable misconfiguration.

### Finding: a reasoned negative result

> Enumeration via SharpHound (326 objects) mapped all trust and control relationships in `...`. Neither the foothold (`janed`) nor the Kerberoastable service account (`svc_sql`) holds any outbound object control or any path to Tier Zero. The domain follows least-privilege for standard and service accounts; the Kerberoastable account is **not over-privileged**, so a successful roast yields no domain escalation. This is a correctly-hardened default, not a misconfiguration.

This is a stronger result than a lucky win: it demonstrates understanding of *what a bad result would look like* (an over-privileged `svc_sql` with a straight edge to Domain Admins) — which is exactly what a defender assesses. In a real environment, the high-value Kerberoast targets are accounts like `svc_backup` (often sweeping rights) or `svc_sccm` (mass software push), which BloodHound would flag with a path to Tier Zero.

---

## Key Findings Summary

1. **RC4 Kerberoasting detection is unreliable in AES domains** — tested and proven to have a 100% miss rate against an AES-default account (`msDS-SupportedEncryptionTypes` blank). Detection must be behavioural (SPN request volume/velocity), not cipher-based.
2. **Audit subcategory override is a hidden second gate** — fine-grained audit settings are silently overridden by legacy category settings unless *"Force audit policy subcategory settings to override category settings"* is enabled. This resolved the 4769/1108 blocker.
3. **The 1108 Event Log service bug is a real telemetry risk** — a documented Windows bug can drop security events before the SIEM ever sees them. Always confirm local Event Viewer before troubleshooting the SIEM pipeline.
4. **LDAP signing defeats Linux BloodHound collectors** — enforced signing forces LDAPS, which ldap3-based tools cannot handle against a self-signed cert; SharpHound-on-Windows is the reliable workaround.
5. **SIEM ingestion lag is real and consistent** — Wazuh timestamps trail DC event-creation time by seconds (agent poll → ship → decode → index). Anchor hunts to the source timestamp and widen the window, or risk missing events that simply haven't finished ingesting.

---

## Detection Coverage Status

| Technique | Attack | Local telemetry | SIEM ingestion | Detection rule |
|---|---|---|---|---|
| T1558.003 Kerberoasting | ✅ `svc_sql` hash pulled | ✅ 4769 (after GPO fix) | ✅ reaching Wazuh | ⚠️ behavioural rule designed, not yet built |
| T1087.002 AD Enumeration | ✅ 326 objects via SharpHound | ⏳ 4662/4661 burst not yet verified | ⏳ pending | ⏳ pending |

---

## Open Items / Next Steps

1. **Build the behavioural Kerberoasting rule in Wazuh** — alert on a single principal requesting many distinct SPN tickets in a short window.
2. **Complete the T1087.002 SIEM hunt** — locate the SharpHound LDAP enumeration burst (Event 4662 / 4661) and build a detection around the volume signature.
3. **(Optional) RC4 before/after experiment** — set `msDS-SupportedEncryptionTypes = 4` on `svc_sql`, re-roast, confirm 4769 now logs 0x17, then revert. Produces a clean "RC4 detection works *only* when the account is misconfigured to allow RC4" demonstration.
4. **ATT&CK Navigator layer export** — the Phase 3 deliverable: a coverage map showing which techniques produce detectable telemetry and which are blind spots. This is the artifact that answers *"how do you know what you're not detecting?"* — blind spots should be chosen and visible, not accidental.

---

## Why This Matters for a SOC Role

Every attack in this phase was run to answer a *defender's* question. The domain was never compromised — and that is irrelevant, because the attack still generated telemetry, and the work was whether that telemetry could be turned into a reliable detection. The most useful output was discovering that a textbook detection **fails** in a realistic configuration, and understanding *why* well enough to replace it. That — not getting Domain Admin — is the job.
