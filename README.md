# ntdescriptor

Parse and decode a base64 `nTSecurityDescriptor` DACL from LDAP beacon output (bloodyAD, ldapsearch BOF, etc.) into human-readable ACEs with full rights decoding, SID resolution, and attack-path filtering.

---

## Requirements

```bash
pip install impacket
```

---

## Usage

```
python3 ntdescriptor.py -sd <BASE64>    -sid <DOMAIN_SID> [options]
python3 ntdescriptor.py -sdfile <PATH>  -sid <DOMAIN_SID> [options]
```

### Arguments

| Flag | Description |
|---|---|
| `-sd <BASE64>` | Base64-encoded `nTSecurityDescriptor` blob (paste directly from beacon output) |
| `-sdfile <PATH>` | Read blob from file instead of command line |
| `-sid <DOMAIN_SID>` | Domain SID for RID resolution (e.g. `S-1-5-21-111-222-333`) — optional but recommended |

### Options

| Flag | Description |
|---|---|
| `--attack-only` | Show only ACEs with offensive-relevant rights — filters noise, surfaces attack paths |
| `--raw` | Print the hex mask value next to decoded rights — useful for debugging |

---

## Examples

### Full DACL decode

```bash
python3 ntdescriptor.py \
    -sd 'AQAEjMwB...' \
    -sid 'S-1-5-21-948911695-1962824894-4291460450'
```

### Attack-relevant ACEs only

```bash
python3 ntdescriptor.py \
    -sd 'AQAEjMwB...' \
    -sid 'S-1-5-21-948911695-1962824894-4291460450' \
    --attack-only
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

### Verbose mask output for debugging

```bash
python3 ntdescriptor.py \
    -sd 'AQAEjMwB...' \
    -sid 'S-1-5-21-948911695-1962824894-4291460450' \
    --attack-only --raw
```

### Read blob from file

```bash
# Extract blob from bloodyAD output
bloodyAD --host dc01.local.htb -u user -p pass \
    get object 'LOCALADMINS' --attr nTSecurityDescriptor \
    | grep nTSecurityDescriptor | awk '{print $2}' > sd.b64

python3 ntdescriptor.py -sdfile sd.b64 -sid 'S-1-5-21-...'
```

---

## Workflow

### 1 — Get the nTSecurityDescriptor from a beacon

Using the `ldapsearch` BOF in Cobalt Strike / Kharon / Adaptix:

```
ldapsearch (distinguishedName=CN=LOCALADMINS,CN=USERS,DC=IT,DC=GCB,DC=LOCAL) -a nTSecurityDescriptor
```

Copy the `nTSecurityDescriptor:` base64 value from the output.

### 2 — Decode it

```bash
python3 ntdescriptor.py -sd '<paste>' -sid 'S-1-5-21-...' --attack-only
```

### 3 — Act on findings

| Finding | Attack path |
|---|---|
| `WriteProperty` on group | Add member → lateral movement |
| `WriteDACL` | Grant self FullControl → anything |
| `WriteOwner` | Take ownership → WriteDACL → FullControl |
| `GenericAll` / `GenericWrite` | Full write access |
| `ForceChangePassword` GUID | Reset user password without knowing current |
| `Self-Membership` GUID | Add yourself to the group |
| `DS-Replication-Get-Changes-All` GUID | DCSync |
| `RBCD` GUID | Write `msDS-AllowedToActOnBehalfOfOtherIdentity` |
| LAPS read GUID | Read plaintext local admin password |
| ADCS enrollment GUID | Request certificate → ESC path |

---

## Attack-relevance logic

`--attack-only` uses different logic for plain vs object ACEs to avoid false positives.

**Plain ACEs** are flagged if the mask contains any of:

| Bit | Right |
|---|---|
| `0x00000020` | WriteProperty |
| `0x00040000` | WriteDACL |
| `0x00080000` | WriteOwner |
| `0x10000000` | GenericAll |
| `0x40000000` | GenericWrite |
| `0x000F01FF` / `0x000F00FF` | FullControl (exact match) |

**Object ACEs** are flagged only if:
- The `ObjectType` GUID is in the known attack GUID list (see below), **OR**
- No `ObjectType` constraint is present AND the mask has dangerous write bits

This prevents the `◄` marker from firing on the 10+ boilerplate Pre-Windows 2000 `ReadProperty` object ACEs that appear on every AD object.

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

---

## Inherited ACEs

`nTSecurityDescriptor` queried via LDAP returns only the **explicit DACL** on the object. Inherited ACEs from parent OUs are not included.

If BloodHound shows a right (e.g. `ReadLAPSPassword`) that doesn't appear in the descriptor:

```bash
# Find the parent OU of the object
ldapsearch (sAMAccountName=IT-APPSRV01$) -a distinguishedName

# Query the OU's descriptor instead
ldapsearch (distinguishedName=OU=Servers,DC=it,DC=gcb,DC=local) -a nTSecurityDescriptor
```

The delegated ACE will be there as an inheritable ACE with `InheritedObjectType` constraining it to computer objects.

---

## LAPS GUID note

LAPS attribute GUIDs are schema-defined and consistent per LAPS version, but differ between **legacy LAPS** (GPO-based, `ms-Mcs-AdmPwd` schema extension) and **Windows LAPS** (built-in since Windows Server 2023 / April 2023 update).

If a LAPS read ACE doesn't surface, run with `--raw` and grep for the RID you expect:

```bash
python3 ntdescriptor.py -sd '...' -sid 'S-1-5-21-...' --raw | grep -A6 "<RID>"
```

Then add the GUID to `ATTACK_GUIDS` and `OBJECT_TYPE_GUIDS` in the script.

---

## SID resolution

Well-known SIDs (BUILTIN groups, NT AUTHORITY, etc.) and common domain RIDs are resolved automatically.

Resolved domain RIDs include: `500` Administrator, `502` krbtgt, `512` Domain Admins, `513` Domain Users, `515` Domain Computers, `516` Domain Controllers, `518` Schema Admins, `519` Enterprise Admins, `525` Protected Users, `526` Key Admins, and others.

Unknown domain RIDs display as `Domain SID RID-XXXX (unknown)` — cross-reference against BloodHound or `ldapsearch` on the SID to resolve.

---

## Dependencies

- [impacket](https://github.com/fortra/impacket)
