#!/usr/bin/env python3
"""
ntdescriptor.py — Parse and decode a base64 nTSecurityDescriptor DACL.

Reads the raw base64 blob from bloodyAD / ldapsearch BOF beacon output and
decodes every ACE into human-readable rights, resolving well-known SIDs and
common domain RIDs automatically.

Usage:
    python3 ntdescriptor.py -sd <BASE64>       -sid <DOMAIN_SID> [options]
    python3 ntdescriptor.py -sdfile <PATH>     -sid <DOMAIN_SID> [options]

Examples:
    # Paste blob directly
    python3 ntdescriptor.py \\
        -sd 'AQAEjMwB...' \\
        -sid 'S-1-5-21-1234567890-1234567890-1234567890'

    # Read blob from file
    python3 ntdescriptor.py \\
        -sdfile descriptor.b64 \\
        -sid 'S-1-5-21-1234567890-1234567890-1234567890'

    # Filter — show only ACEs with offensive-relevant rights
    python3 ntdescriptor.py \\
        -sd 'AQAEjMwB...' \\
        -sid 'S-1-5-21-1234567890-1234567890-1234567890' \\
        --attack-only

    # Show raw mask values alongside decoded rights
    python3 ntdescriptor.py \\
        -sd 'AQAEjMwB...' \\
        -sid 'S-1-5-21-1234567890-1234567890-1234567890' \\
        --raw

Dependencies:
    pip install impacket
"""

import sys
import argparse
import base64
import struct

try:
    from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR
    from impacket.uuid import bin_to_string
except ImportError:
    print("[!] impacket not found. Install with: pip install impacket", file=sys.stderr)
    sys.exit(1)


# ──────────────────────────────────────────────────────────────────────────────
# SID tables
# ──────────────────────────────────────────────────────────────────────────────

WELL_KNOWN_SIDS = {
    "S-1-0-0":       "Null Authority",
    "S-1-1-0":       "Everyone",
    "S-1-2-0":       "Local",
    "S-1-3-0":       "Creator Owner",
    "S-1-3-1":       "Creator Group",
    "S-1-5-1":       "Dialup",
    "S-1-5-2":       "Network",
    "S-1-5-4":       "Interactive",
    "S-1-5-6":       "Service",
    "S-1-5-7":       "Anonymous",
    "S-1-5-9":       "Enterprise Domain Controllers",
    "S-1-5-10":      "Self",
    "S-1-5-11":      "Authenticated Users",
    "S-1-5-12":      "Restricted Code",
    "S-1-5-13":      "Terminal Server Users",
    "S-1-5-14":      "Remote Interactive Logon",
    "S-1-5-15":      "This Organization",
    "S-1-5-17":      "IUSR",
    "S-1-5-18":      "SYSTEM",
    "S-1-5-19":      "Local Service",
    "S-1-5-20":      "Network Service",
    "S-1-5-32-544":  "BUILTIN\\Administrators",
    "S-1-5-32-545":  "BUILTIN\\Users",
    "S-1-5-32-546":  "BUILTIN\\Guests",
    "S-1-5-32-547":  "BUILTIN\\Power Users",
    "S-1-5-32-548":  "BUILTIN\\Account Operators",
    "S-1-5-32-549":  "BUILTIN\\Server Operators",
    "S-1-5-32-550":  "BUILTIN\\Print Operators",
    "S-1-5-32-551":  "BUILTIN\\Backup Operators",
    "S-1-5-32-552":  "BUILTIN\\Replicators",
    "S-1-5-32-554":  "BUILTIN\\Pre-Windows 2000 Compatible Access",
    "S-1-5-32-555":  "BUILTIN\\Remote Desktop Users",
    "S-1-5-32-556":  "BUILTIN\\Network Configuration Operators",
    "S-1-5-32-557":  "BUILTIN\\Incoming Forest Trust Builders",
    "S-1-5-32-558":  "BUILTIN\\Performance Monitor Users",
    "S-1-5-32-559":  "BUILTIN\\Performance Log Users",
    "S-1-5-32-560":  "BUILTIN\\Windows Authorization Access Group",
    "S-1-5-32-561":  "BUILTIN\\Terminal Server License Servers",
    "S-1-5-32-562":  "BUILTIN\\Distributed COM Users",
    "S-1-5-32-568":  "BUILTIN\\IIS_IUSRS",
    "S-1-5-32-569":  "BUILTIN\\Cryptographic Operators",
    "S-1-5-32-573":  "BUILTIN\\Event Log Readers",
    "S-1-5-32-574":  "BUILTIN\\Certificate Service DCOM Access",
    "S-1-5-32-575":  "BUILTIN\\RDS Remote Access Servers",
    "S-1-5-32-576":  "BUILTIN\\RDS Endpoint Servers",
    "S-1-5-32-577":  "BUILTIN\\RDS Management Servers",
    "S-1-5-32-578":  "BUILTIN\\Hyper-V Administrators",
    "S-1-5-32-579":  "BUILTIN\\Access Control Assistance Operators",
    "S-1-5-32-580":  "BUILTIN\\Remote Management Users",
}

# Well-known domain RIDs (suffix of domain SID)
DOMAIN_RIDS = {
    "498":  "Enterprise Read-Only Domain Controllers",
    "500":  "Administrator",
    "501":  "Guest",
    "502":  "krbtgt",
    "512":  "Domain Admins",
    "513":  "Domain Users",
    "514":  "Domain Guests",
    "515":  "Domain Computers",
    "516":  "Domain Controllers",
    "517":  "Cert Publishers",
    "518":  "Schema Admins",
    "519":  "Enterprise Admins",
    "520":  "Group Policy Creator Owners",
    "521":  "Read-Only Domain Controllers",
    "522":  "Cloneable Domain Controllers",
    "525":  "Protected Users",
    "526":  "Key Admins",
    "527":  "Enterprise Key Admins",
    "553":  "RAS and IAS Servers",
    "571":  "Allowed RODC Password Replication Group",
    "572":  "Denied RODC Password Replication Group",
}


# ──────────────────────────────────────────────────────────────────────────────
# Object type GUIDs (extended rights + property sets)
# ──────────────────────────────────────────────────────────────────────────────

OBJECT_TYPE_GUIDS = {
    # Extended rights
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes",
    "1131f6ab-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Synchronize",
    "1131f6ac-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Manage-Topology",
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes-All  ← DCSync",
    "1131f6ae-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes-In-Filtered-Set",
    "00299570-246d-11d0-a768-00aa006e0529": "User-Force-Change-Password  ← ForceChangePassword",
    "ab721a53-1e2f-11d0-9819-00aa0040529b": "User-Change-Password",
    "ab721a54-1e2f-11d0-9819-00aa0040529b": "Send-As",
    "ab721a56-1e2f-11d0-9819-00aa0040529b": "Receive-As",
    "ab721a55-1e2f-11d0-9819-00aa0040529b": "Send-To",
    "9923a32a-3607-11d2-b9be-0000f87a36b2": "DS-Install-Replica",
    "69ae6200-7f46-11d2-b9ad-00c04f79f805": "DS-Check-Stale-Phantoms",
    "3e0f7e18-2c7a-4c10-ba82-4d926db99a3e": "DS-Clone-Domain-Controller",
    "084c93a2-620d-4879-a836-f0ae47de0e89": "DS-Read-Partition-Secrets",
    "94825a8d-b171-4116-8146-1e34d8f54401": "DS-Write-Partition-Secrets",
    "4ecc03fe-ffc0-4947-b630-eb672a8a9dbc": "DS-Query-Self-Quota",
    "5f202010-79a5-11d0-9020-00c04fc2d4cf": "User-Logon",
    "bc0ac240-79a9-11d0-9020-00c04fc2d4cf": "Membership  (group member read)",
    "a05b8cc2-17bc-4802-a710-e7c15ab866a2": "Certification-Authority-Autoenrollment",
    "0e10c968-78fb-11d2-90d4-00c04f79dc55": "Certificate-Enrollment  ← ADCS ESC",
    "a05b8cc2-17bc-4802-a710-e7c15ab866a2": "Autoenrollment",
    # Property sets
    "bf9679c0-0de6-11d0-a285-00aa003049e2": "Self-Membership  ← AddSelf to group",
    "bf9679a8-0de6-11d0-a285-00aa003049e2": "msDS-AllowedToActOnBehalfOfOtherIdentity  ← RBCD write",
    "4c164200-20c0-11d0-a768-00aa006e0529": "User-Account-Restrictions",
    "77b5b886-944a-11d1-aebd-0000f80367c1": "Personal-Information",
    "e45795b2-9455-11d1-aebd-0000f80367c1": "Email-Information",
    "e45795b3-9455-11d1-aebd-0000f80367c1": "Web-Information",
    "e48d0154-bcf8-11d1-8702-00c04fb96050": "Public-Information",
    "037088f8-0ae1-11d2-b422-00a0c968f939": "Remote-Access-Information",
    "b8119fd0-04f6-4762-ab7a-4986c76b3f9a": "Other-Domain-Parameters",
    "72e39547-7b18-11d1-adef-00c04fd8d5cd": "DNS-Host-Name-Attributes",
    "f3a64788-5306-11d1-a9c5-0000f80367c1": "Service-Principal-Name",
    "e48d0154-bcf8-11d1-8702-00c04fb96050": "Public-Information",
    # LAPS (legacy GPO-based)
    "91e10b44-f267-4082-9210-b8f9ee08e4eb": "ms-Mcs-AdmPwd  ← LAPS password READ",
    "2a90118e-8185-4539-b84c-8a02540fb8ba": "LAPS property set  ← ReadLAPSPassword",
    # LAPS (Windows LAPS / new)
    "e362ed86-b728-0842-b27d-2dea7a9df218": "ms-LAPS-EncryptedPassword  ← LAPS password READ",
    "a10f0905-4e9d-4572-bdb5-e0e6e1f1b0a6": "ms-LAPS-EncryptedPasswordHistory",
    "b0f8dc99-4903-4270-aab7-1b66bef93dca": "ms-Mcs-AdmPwdExpirationTime  ← LAPS expiry (write = force reset)",
}


# ──────────────────────────────────────────────────────────────────────────────
# Rights decoding
# ──────────────────────────────────────────────────────────────────────────────

# AD-specific access rights (ADS_RIGHT_DS_*) — per MS-ADTS 5.1.3.2
AD_RIGHTS = [
    (0x00000001, "CreateChild"),
    (0x00000002, "DeleteChild"),
    (0x00000004, "ListContents"),
    (0x00000008, "Self"),               # DS_SELF_WRITE (write to self / validated writes)
    (0x00000010, "ReadProperty"),
    (0x00000020, "WriteProperty"),      # ← BloodHound GenericWrite on group/user objects
    (0x00000040, "DeleteTree"),
    (0x00000080, "ListObject"),
    (0x00000100, "ControlAccess"),      # Extended rights (DCSync, ForceChangePassword, etc.)
    (0x00010000, "Delete"),
    (0x00020000, "ReadControl"),
    (0x00040000, "WriteDACL"),
    (0x00080000, "WriteOwner"),
    (0x10000000, "GenericAll"),
    (0x20000000, "GenericExecute"),
    (0x40000000, "GenericWrite"),
    (0x80000000, "GenericRead"),
]

# Composite masks that map to a single label
COMPOSITE_MASKS = {
    0x000F01FF: "FullControl",
    0x000F00FF: "FullControl(AD)",
    0x00020094: "ReadControl+ListContents+ReadProperty",
    0x00020014: "WriteDACL+ReadControl",
    0x001F01FF: "FullControl(file)",
}

# Rights considered interesting for attack paths
# Individual attack-relevant bits for bitwise AND checks
ATTACK_BITS = {
    0x00000020,  # WriteProperty
    0x00040000,  # WriteDACL
    0x00080000,  # WriteOwner
    0x10000000,  # GenericAll
    0x40000000,  # GenericWrite
}

# Exact composite mask values that mean full/dangerous access
ATTACK_EXACT = {
    0x000F01FF,  # FullControl
    0x000F00FF,  # FullControl(AD)
    0x001F01FF,  # FullControl(file)
}

# GUIDs that are attack-relevant when granted via an object ACE
ATTACK_GUIDS = {
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",  # DS-Replication-Get-Changes
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",  # DS-Replication-Get-Changes-All (DCSync)
    "00299570-246d-11d0-a768-00aa006e0529",  # User-Force-Change-Password
    "ab721a53-1e2f-11d0-9819-00aa0040529b",  # User-Change-Password
    "bf9679c0-0de6-11d0-a285-00aa003049e2",  # Self-Membership (AddSelf to group)
    "bf9679a8-0de6-11d0-a285-00aa003049e2",  # msDS-AllowedToActOnBehalfOfOtherIdentity (RBCD)
    "0e10c968-78fb-11d2-90d4-00c04f79dc55",  # Certificate-Enrollment (ADCS ESC)
    "a05b8cc2-17bc-4802-a710-e7c15ab866a2",  # Autoenrollment
    "ab721a54-1e2f-11d0-9819-00aa0040529b",  # Send-As
    "ab721a56-1e2f-11d0-9819-00aa0040529b",  # Receive-As
    "1131f6ac-9c07-11d1-f79f-00c04fc2dcd2",  # DS-Replication-Synchronize
    # Sensitive readable attributes — read access IS attack-relevant
    "91e10b44-f267-4082-9210-b8f9ee08e4eb",  # ms-Mcs-AdmPwd (legacy LAPS password)
    "2a90118e-8185-4539-b84c-8a02540fb8ba",  # LAPS property set (ReadLAPSPassword)
    "e362ed86-b728-0842-b27d-2dea7a9df218",  # ms-LAPS-EncryptedPassword (new LAPS)
    "a10f0905-4e9d-4572-bdb5-e0e6e1f1b0a6",  # ms-LAPS-EncryptedPasswordHistory
    "b0f8dc99-4903-4270-aab7-1b66bef93dca",  # ms-Mcs-AdmPwdExpirationTime (expiry write = reset)
}


def decode_mask(mask: int) -> list[str]:
    if mask in COMPOSITE_MASKS:
        return [COMPOSITE_MASKS[mask]]
    rights = [name for bit, name in AD_RIGHTS if mask & bit]
    return rights if rights else [f"0x{mask:08X}"]


def is_attack_relevant(mask: int, ace_type: str, object_guid: str | None = None) -> bool:
    """
    Determine if an ACE is attack-relevant.

    Plain ACEs  — dangerous if mask has any ATTACK_BITS set, or is an ATTACK_EXACT value.
    Object ACEs — dangerous only if:
                  (a) the ObjectType GUID is in ATTACK_GUIDS, OR
                  (b) no ObjectType constraint AND mask has dangerous write bits
    WriteDACL / WriteOwner / GenericAll are always dangerous regardless of ACE type.
    """
    is_object_ace = ace_type in (
        "ACCESS_ALLOWED_OBJECT_ACE",
        "ACCESS_DENIED_OBJECT_ACE",
        "ACCESS_ALLOWED_CALLBACK_OBJECT_ACE",
    )

    def has_dangerous_bits(m: int) -> bool:
        return m in ATTACK_EXACT or any(m & bit for bit in ATTACK_BITS)

    # WriteDACL / WriteOwner / GenericAll — always dangerous
    always_dangerous = {0x00040000, 0x00080000, 0x10000000}
    if any(mask & bit for bit in always_dangerous):
        return True

    if is_object_ace:
        if object_guid and object_guid.lower() in ATTACK_GUIDS:
            return True
        # No GUID constraint on the object ACE — treat as unrestricted
        if not object_guid:
            return has_dangerous_bits(mask)
        return False

    # Plain ACE
    return has_dangerous_bits(mask)


# ──────────────────────────────────────────────────────────────────────────────
# SID resolution
# ──────────────────────────────────────────────────────────────────────────────

def resolve_sid(sid: str, domain_sid: str) -> str:
    if sid in WELL_KNOWN_SIDS:
        return WELL_KNOWN_SIDS[sid]
    if domain_sid and sid.startswith(domain_sid + "-"):
        rid = sid.split("-")[-1]
        rid_name = DOMAIN_RIDS.get(rid)
        if rid_name:
            return f"{rid_name} (RID {rid})"
        return f"Domain SID RID-{rid} (unknown)"
    return sid


# ──────────────────────────────────────────────────────────────────────────────
# ACE type labels
# ──────────────────────────────────────────────────────────────────────────────

ACE_TYPE_LABELS = {
    "ACCESS_ALLOWED_ACE":             "ALLOW",
    "ACCESS_DENIED_ACE":              "DENY ",
    "ACCESS_ALLOWED_OBJECT_ACE":      "ALLOW-OBJ",
    "ACCESS_DENIED_OBJECT_ACE":       "DENY-OBJ ",
    "SYSTEM_AUDIT_ACE":               "AUDIT",
    "SYSTEM_AUDIT_OBJECT_ACE":        "AUDIT-OBJ",
    "ACCESS_ALLOWED_CALLBACK_ACE":    "ALLOW-CB",
    "ACCESS_DENIED_CALLBACK_ACE":     "DENY-CB ",
}

ATTACK_ACE_TYPES = {
    "ACCESS_ALLOWED_ACE",
    "ACCESS_ALLOWED_OBJECT_ACE",
    "ACCESS_ALLOWED_CALLBACK_ACE",
}


# ──────────────────────────────────────────────────────────────────────────────
# Object type GUID extraction
# ──────────────────────────────────────────────────────────────────────────────

def get_object_type(ace) -> str | None:
    """Extract and resolve ObjectType GUID from an object ACE if present."""
    try:
        # Direct field access — impacket structures don't reliably support .get()
        flags = int(ace['Ace']['Flags'])
        # ACE_OBJECT_TYPE_PRESENT = 0x01
        if not (flags & 0x01):
            return None
        obj_type_raw = ace['Ace']['ObjectType']
        if not obj_type_raw:
            return None
        guid = bin_to_string(bytes(obj_type_raw)).lower()
        label = OBJECT_TYPE_GUIDS.get(guid)
        return f"{label}  [{guid}]" if label else guid
    except Exception:
        return None


# ──────────────────────────────────────────────────────────────────────────────
# Main parser
# ──────────────────────────────────────────────────────────────────────────────

def parse_descriptor(b64_data: str, domain_sid: str,
                     attack_only: bool = False, show_raw: bool = False):

    b64_data = b64_data.strip()
    try:
        raw = base64.b64decode(b64_data)
    except Exception as e:
        print(f"[!] Base64 decode failed: {e}", file=sys.stderr)
        sys.exit(1)

    sd = SR_SECURITY_DESCRIPTOR()
    sd.fromString(raw)

    # ── Header ────────────────────────────────────────────────────────────────
    owner_sid = sd['OwnerSid'].formatCanonical() if sd['OwnerSid'] else "N/A"
    group_sid = sd['GroupSid'].formatCanonical() if sd['GroupSid'] else "N/A"

    print(f"\n{'─'*70}")
    print(f"  Owner : {resolve_sid(owner_sid, domain_sid)}  [{owner_sid}]")
    print(f"  Group : {resolve_sid(group_sid, domain_sid)}  [{group_sid}]")
    print(f"{'─'*70}\n")

    if not sd['Dacl']:
        print("[!] No DACL present (object is unprotected)")
        return

    aces = sd['Dacl']['Data']
    total = len(aces)
    filtered = 0

    for ace in aces:
        type_name = ace['TypeName']
        mask      = ace['Ace']['Mask']['Mask']
        sid       = ace['Ace']['Sid'].formatCanonical()
        object_type = get_object_type(ace)

        # Extract bare GUID for attack relevance check (strip label annotation)
        object_guid = None
        if object_type:
            # Format is "Label  [guid]" or just "guid"
            if '[' in object_type:
                object_guid = object_type.split('[')[1].rstrip(']').strip()
            else:
                object_guid = object_type.strip()

        if attack_only:
            if type_name not in ATTACK_ACE_TYPES:
                continue
            if not is_attack_relevant(mask, type_name, object_guid):
                continue
            filtered += 1

        type_label   = ACE_TYPE_LABELS.get(type_name, type_name)
        sid_label    = resolve_sid(sid, domain_sid)
        rights       = decode_mask(mask)

        # Highlight lines
        marker = ""
        if type_name in ATTACK_ACE_TYPES and is_attack_relevant(mask, type_name, object_guid):
            marker = "  ◄"

        print(f"  [{type_label}]{marker}")
        print(f"    SID    : {sid_label}")
        if sid_label != sid:
            print(f"             {sid}")
        if show_raw:
            print(f"    Mask   : 0x{mask:08X}")
        print(f"    Rights : {', '.join(rights)}")
        if object_type:
            print(f"    ObjType: {object_type}")
        print()

    print(f"{'─'*70}")
    if attack_only:
        print(f"  {filtered} attack-relevant ACEs  (of {total} total)")
    else:
        print(f"  {total} ACEs total  |  use --attack-only to filter")
    print(f"{'─'*70}\n")


# ──────────────────────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="ntdescriptor.py",
        description="Decode a base64 nTSecurityDescriptor DACL from LDAP/beacon output.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument(
        "-sd", metavar="BASE64",
        help="Base64-encoded nTSecurityDescriptor blob",
    )
    src.add_argument(
        "-sdfile", metavar="PATH",
        help="File containing the base64 blob (one line)",
    )

    parser.add_argument(
        "-sid", metavar="DOMAIN_SID", required=False, default="",
        help="Domain SID for RID resolution (e.g. S-1-5-21-111-222-333). "
             "Optional — without it domain accounts show as raw SIDs.",
    )
    parser.add_argument(
        "--attack-only", action="store_true",
        help="Show only ACEs with offensive-relevant rights "
             "(WriteDACL, WriteOwner, WriteProperty, ControlAccess, GenericAll/Write, FullControl)",
    )
    parser.add_argument(
        "--raw", action="store_true",
        help="Also print the raw hex mask value next to decoded rights",
    )

    args = parser.parse_args()

    if args.sdfile:
        try:
            with open(args.sdfile, "r") as fh:
                b64_data = fh.read().strip()
        except OSError as e:
            print(f"[!] Cannot read file: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        b64_data = args.sd

    parse_descriptor(
        b64_data=b64_data,
        domain_sid=args.sid,
        attack_only=args.attack_only,
        show_raw=args.raw,
    )


if __name__ == "__main__":
    main()
