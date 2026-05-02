# ntdescriptor-tools

Parse and decode `nTSecurityDescriptor` DACLs from LDAP beacon output (ldapsearch BOF, bloodyAD) into human-readable ACEs — with attack-path filtering, SID resolution, object GUID labelling, and batch processing.

No PowerView, no PowerShell, no execute-assembly required.

---

## Tools

| Script | Purpose |
|---|---|
| `ntdescriptor.py` | Decode a single base64 nTSecurityDescriptor blob into ACEs |
| `sd_batch.py` | Parse ldapsearch BOF output containing multiple descriptors and run each through `ntdescriptor.py` |

---

## Requirements

```bash
pip install impacket
```

Both scripts must be in the same directory, or pass `--ntdescriptor <path>` to `sd_batch.py`.

---

# ntdescriptor.py

Decodes a base64 `nTSecurityDescriptor` blob into every ACE with full rights decoding, SID resolution, and object GUID labelling. The `--attack-only` flag filters noise and surfaces only ACEs with offensive-relevant rights.

## Usage

```
python3 ntdescriptor.py -sd <BASE64> -sid <DOMAIN_SID> [options]
python3 ntdescriptor.py -sdfile <PATH> -sid <DOMAIN_SID> [options]
```

### Arguments

| Flag | Description |
|---|---|
| `-sd <BASE64>` | Base64-encoded `nTSecurityDescriptor` blob (paste from beacon output) |
| `-sdfile <PATH>` | Read blob from file instead of command line |
| `-sid <DOMAIN_SID>` | Domain SID for RID resolution — optional but recommended |

### Options

| Flag | Description |
|---|---|
| `--attack-only` | Show only ACEs with offensive-relevant rights — suppresses boilerplate |
| `--raw` | Print hex mask value next to decoded rights — useful for debugging |

## Examples

### Full DACL decode

```bash
python3 ntdescriptor.py -sd 'AQAEjMwB...' -sid 'S-1-5-21-111-222-333'
```

### Attack-relevant ACEs only

```bash
python3 ntdescriptor.py -sd 'AQAEjMwB...' -sid 'S-1-5-21-111-222-333' --attack-only
```

```
──────────────────────────────────────────────────────────────────────
  Owner : Domain Admins (RID 512)  [S-1-5-21-...-512]
  Group : Domain Admins (RID 512)  [S-1-5-21-...-512]
──────────────────────────────────────────────────────────────────────

  [ALLOW]  ◄
    SID    : LOCALADMINS (RID 1124)
    Rights : ListContents, ReadProperty, WriteProperty, ReadControl

  [ALLOW-OBJ]  ◄
    SID    : LOCALADMINS (RID 1108)
    Rights : ReadProperty
    ObjType: ms-Mcs-AdmPwd  ← LAPS password READ  [91e10b44-...]

  [ALLOW]  ◄
    SID    : Domain Admins (RID 512)
    Rights : FullControl

──────────────────────────────────────────────────────────────────────
  3 attack-relevant ACEs  (of 34 total)
──────────────────────────────────────────────────────────────────────
```

### Debug mask values

```bash
python3 ntdescriptor.py -sd 'AQAEjMwB...' -sid 'S-1-5-21-111-222-333' --attack-only --raw
```

### Read blob from file

```bash
python3 ntdescriptor.py -sdfile descriptor.b64 -sid 'S-1-5-21-111-222-333' --attack-only
```

## Workflow

### 1 — Get the nTSecurityDescriptor from a beacon

Using the `ldapsearch` BOF in AdaptixC2 / Cobalt Strike / Havoc:

```
ldapsearch (distinguishedName=CN=LOCALADMINS,CN=USERS,DC=IT,DC=corp,DC=local) -a nTSecurityDescriptor
```

Copy the `nTSecurityDescriptor:` base64 value from the beacon output.

### 2 — Decode

```bash
python3 ntdescriptor.py -sd '<paste>' -sid 'S-1-5-21-...' --attack-only
```

### 3 — Act on findings

| Finding | Attack path |
|---|---|
| `WriteProperty` on group | Add member → lateral movement |
| `WriteDACL` | Grant self FullControl |
| `WriteOwner` | Take ownership → WriteDACL → FullControl |
| `GenericAll` / `GenericWrite` | Full write access |
| `ForceChangePassword` GUID | Reset password without knowing current |
| `Self-Membership` GUID | Add yourself to the group |
| `DS-Replication-Get-Changes-All` GUID | DCSync |
| `msDS-AllowedToActOnBehalfOfOtherIdentity` GUID | RBCD write |
| LAPS read GUID | Read plaintext local admin password |
| ADCS enrollment GUID | Request certificate |

## Attack-relevance logic

`--attack-only` uses different logic for plain vs object ACEs to avoid false positives from the 10+ boilerplate Pre-Windows 2000 `ReadProperty` object ACEs that appear on every AD object.

**Plain ACEs** — flagged if mask contains any of:

| Bit | Right |
|---|---|
| `0x00000020` | WriteProperty |
| `0x00040000` | WriteDACL |
| `0x00080000` | WriteOwner |
| `0x10000000` | GenericAll |
| `0x40000000` | GenericWrite |
| `0x000F01FF` / `0x000F00FF` | FullControl (exact match) |

**Object ACEs** — flagged only if the `ObjectType` GUID is in the known attack GUID list, or no GUID constraint is present with dangerous write bits.

### Known attack GUIDs

| GUID | Right | Attack |
|---|---|---|
| `1131f6ad-...` | DS-Replication-Get-Changes-All | DCSync |
| `1131f6aa-...` | DS-Replication-Get-Changes | DCSync (partial) |
| `00299570-...` | User-Force-Change-Password | ForceChangePassword |
| `bf9679c0-...` | Self-Membership | AddSelf to group |
| `bf9679a8-...` | msDS-AllowedToActOnBehalfOfOtherIdentity | RBCD write |
| `0e10c968-...` | Certificate-Enrollment | ADCS ESC |
| `91e10b44-...` | ms-Mcs-AdmPwd | Legacy LAPS password read |
| `2a90118e-...` | LAPS property set | ReadLAPSPassword |
| `e362ed86-...` | ms-LAPS-EncryptedPassword | New LAPS password read |

## Inherited ACEs

`nTSecurityDescriptor` via LDAP returns only the **explicit DACL**. Inherited ACEs from parent OUs are not included. If BloodHound shows a right that doesn't appear in the descriptor, query the parent OU:

```bash
# Find parent OU of the object
ldapsearch (sAMAccountName=IT-APPSRV01$) -a distinguishedName

# Query OU descriptor
ldapsearch (distinguishedName=OU=Servers,DC=corp,DC=local) -a nTSecurityDescriptor
```

## LAPS GUID note

LAPS attribute GUIDs differ between legacy LAPS (GPO-based) and Windows LAPS (built-in since April 2023). If a LAPS read ACE doesn't surface, run `--raw` and grep for the RID you expect:

```bash
python3 ntdescriptor.py -sd '...' -sid 'S-1-5-21-...' --raw | grep -A6 "<RID>"
```

Then add the GUID to `ATTACK_GUIDS` and `OBJECT_TYPE_GUIDS` in the script.

---

# sd_batch.py

Parse ldapsearch BOF output containing **multiple `nTSecurityDescriptor` blobs** and run each through `ntdescriptor.py --attack-only` automatically. Useful when querying all groups, OUs, or computers in a domain.

## Usage

```
python3 sd_batch.py -f <FILE> -sid <DOMAIN_SID> [options]
python3 sd_batch.py -sid <DOMAIN_SID> [options] < beacon_output.txt
```

### Arguments

| Flag | Description |
|---|---|
| `-f <FILE>` | Beacon output file containing one or more `nTSecurityDescriptor:` entries |
| `-sid <DOMAIN_SID>` | Domain SID for RID resolution |

### Options

| Flag | Description |
|---|---|
| `--hits-only` | Suppress clean objects — only print objects with attack-relevant ACEs |
| `--foreign-sid <SID>` | Only show ACEs where the principal belongs to this domain SID — useful for cross-domain ACL analysis |
| `--raw` | Pass `--raw` to ntdescriptor for hex mask values |
| `--ntdescriptor <PATH>` | Path to ntdescriptor.py if not in same directory |

## Examples

### Basic batch run

```bash
python3 sd_batch.py -f groups_output.txt -sid 'S-1-5-21-111-222-333' --hits-only
```

### Cross-domain — show only ACEs from a foreign domain

Useful when querying INTERNAL.DOMAIN objects and you only want to see what YOUR domain (e.g. MSP.LOCAL) has rights over:

```bash
python3 sd_batch.py -f groups_output.txt -sid 'S-1-5-21-111-222-333' --foreign-sid 'S-1-5-21-444-555-666' --hits-only
```

### From stdin

```bash
python3 sd_batch.py -sid 'S-1-5-21-111-222-333' --hits-only < beacon_output.txt
```

## Output

```
======================================================================
  Object 7/8  ◄ ATTACK-RELEVANT ACEs
======================================================================

──────────────────────────────────────────────────────────────────────
  Owner : Domain Admins (RID 512)  [S-1-5-21-...-512]
  Group : Domain Admins (RID 512)  [S-1-5-21-...-512]
──────────────────────────────────────────────────────────────────────

  [ALLOW-OBJ]  ◄
    SID    : S-1-5-21-444-555-666-1107
    Rights : Self
    ObjType: Self-Membership  ← AddSelf to group  [bf9679c0-...]

  [ALLOW]  ◄
    SID    : Domain Admins (RID 512)
    Rights : FullControl

──────────────────────────────────────────────────────────────────────
  6 attack-relevant ACEs  (of 35 total)
──────────────────────────────────────────────────────────────────────

======================================================================
  Summary: 2 object(s) with attack-relevant ACEs / 8 total
           6 clean object(s)
======================================================================
```

## Workflow

### Query all groups and batch decode

```bash
# 1. Dump all group descriptors from beacon
ldapsearch (objectClass=group) -a nTSecurityDescriptor --dc dc01.corp.local --dn "DC=corp,DC=local"

# 2. Save beacon output to file, then batch decode
python3 sd_batch.py -f groups_output.txt -sid 'S-1-5-21-111-222-333' --hits-only
```

### Cross-domain group ACL analysis (no PowerView needed)

```bash
# Query internal domain group descriptors via ldapsearch BOF
ldapsearch (objectClass=group) -a nTSecurityDescriptor --dc internal-dc01.internal.corp.local --dn "DC=internal,DC=corp,DC=local"

# Find which MSP.LOCAL principals have rights on INTERNAL objects
python3 sd_batch.py -f internal_groups.txt -sid 'S-1-5-21-111-222-333' --foreign-sid 'S-1-5-21-444-555-666' --hits-only
```

This replaces the PowerView approach:

```powershell
# What most guides tell you (noisy, needs PS, needs execute-assembly or powerpick)
Get-DomainObjectAcl -Domain internal.corp.local -ResolveGUIDs | ...
```

With a BOF + Kali-side Python approach that generates no PowerShell events and no .NET assembly load.

---

## References

- [MS-ADTS §5.1.3.2 — nTSecurityDescriptor](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/20504d60-43ec-458f-bc7a-754353dab0e7)
- [MS-DTYP §2.4.6 — SECURITY_DESCRIPTOR](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7d4dac05-9cef-4563-a058-f108abecce1d)
- [impacket](https://github.com/fortra/impacket)
- [bloodyAD](https://github.com/CravateRouge/bloodyAD)
