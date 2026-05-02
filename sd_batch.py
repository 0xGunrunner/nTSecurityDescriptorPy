#!/usr/bin/env python3
"""
sd_batch.py — Parse ldapsearch BOF output and run each nTSecurityDescriptor
blob through ntdescriptor.py --attack-only.

Usage:
    # Pipe directly from beacon log file
    python3 sd_batch.py -f beacon_output.txt -sid 'S-1-5-21-111-222-333'

    # Read from stdin (paste beacon output)
    python3 sd_batch.py -sid 'S-1-5-21-111-222-333' < beacon_output.txt

    # Only show objects with hits (suppress clean objects)
    python3 sd_batch.py -f output.txt -sid 'S-1-5-21-111-222-333' --hits-only

    # Also pass --raw to ntdescriptor for mask values
    python3 sd_batch.py -f output.txt -sid 'S-1-5-21-111-222-333' --raw
"""

import sys
import argparse
import subprocess
import re
from pathlib import Path


def extract_blobs(text: str) -> list[str]:
    """
    Extract base64 nTSecurityDescriptor blobs from ldapsearch BOF output.
    Handles both single-line and wrapped multi-line blobs.
    """
    blobs = []
    current_blob = None

    for line in text.splitlines():
        line = line.rstrip()

        # Start of a new blob
        if line.startswith("nTSecurityDescriptor:"):
            if current_blob is not None:
                blobs.append(current_blob.strip())
            value = line.split(":", 1)[1].strip()
            current_blob = value

        elif current_blob is not None:
            # Continuation line — raw base64 has no spaces and no colons
            stripped = line.strip()
            if stripped and not stripped.startswith("[") and not stripped.startswith("-") and not stripped.startswith("*"):
                # Looks like base64 continuation
                if re.match(r'^[A-Za-z0-9+/=]+$', stripped):
                    current_blob += stripped
                else:
                    # Not base64 — end of blob
                    blobs.append(current_blob.strip())
                    current_blob = None
            elif stripped.startswith("----") or stripped.startswith("[") or stripped.startswith("retrieved"):
                if current_blob:
                    blobs.append(current_blob.strip())
                current_blob = None

    if current_blob:
        blobs.append(current_blob.strip())

    # Deduplicate while preserving order
    seen = set()
    unique = []
    for b in blobs:
        if b not in seen:
            seen.add(b)
            unique.append(b)

    return unique


def run_ntdescriptor(blob: str, sid: str, raw: bool, ntdescriptor_path: str) -> tuple[str, bool]:
    """
    Run ntdescriptor.py on a single blob.
    Returns (output, had_hits).
    """
    cmd = [sys.executable, ntdescriptor_path, "-sd", blob, "--attack-only"]
    if sid:
        cmd += ["-sid", sid]
    if raw:
        cmd.append("--raw")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        output = result.stdout + result.stderr
        # Check if any attack-relevant ACEs were found (more than 0)
        had_hits = bool(re.search(r'^\s+\d+ attack-relevant ACEs\s+\(of', output, re.MULTILINE) and
                        not re.search(r'0 attack-relevant ACEs', output))
        return output, had_hits
    except subprocess.TimeoutExpired:
        return "[!] Timeout parsing descriptor\n", False
    except Exception as e:
        return f"[!] Error: {e}\n", False


def main():
    parser = argparse.ArgumentParser(
        prog="sd_batch.py",
        description="Parse ldapsearch BOF output and run each nTSecurityDescriptor through ntdescriptor.py.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("-f", "--file", metavar="PATH",
                        help="Beacon output file (default: stdin)")
    parser.add_argument("-sid", metavar="DOMAIN_SID", default="",
                        help="Domain SID for RID resolution (e.g. S-1-5-21-111-222-333)")
    parser.add_argument("--foreign-sid", metavar="DOMAIN_SID", default="",
                        help="Only show ACEs where the principal belongs to this domain SID "
                             "(e.g. filter for MSP.LOCAL principals on INTERNAL.MSP.LOCAL objects)")
    parser.add_argument("--hits-only", action="store_true",
                        help="Only print output for objects with attack-relevant ACEs")
    parser.add_argument("--raw", action="store_true",
                        help="Pass --raw to ntdescriptor.py (show hex mask values)")
    parser.add_argument("--ntdescriptor", default="ntdescriptor.py", metavar="PATH",
                        help="Path to ntdescriptor.py (default: ntdescriptor.py in same dir)")
    args = parser.parse_args()

    # Resolve ntdescriptor.py path
    ntdesc_path = args.ntdescriptor
    if not Path(ntdesc_path).exists():
        # Try same directory as this script
        candidate = Path(__file__).parent / "ntdescriptor.py"
        if candidate.exists():
            ntdesc_path = str(candidate)
        else:
            print(f"[!] ntdescriptor.py not found at '{args.ntdescriptor}'. Use --ntdescriptor PATH", file=sys.stderr)
            sys.exit(1)

    # Read input
    if args.file:
        try:
            text = Path(args.file).read_text()
        except OSError as e:
            print(f"[!] Cannot read file: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        text = sys.stdin.read()

    blobs = extract_blobs(text)

    if not blobs:
        print("[!] No nTSecurityDescriptor blobs found in input.", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Found {len(blobs)} descriptor(s) — running ntdescriptor.py --attack-only on each\n")

    hits_total  = 0
    clean_total = 0

    for i_obj, blob in enumerate(blobs, 1):
        output, had_hits = run_ntdescriptor(blob, args.sid, args.raw, ntdesc_path)

        if had_hits:
            # Apply --foreign-sid filter if specified
            if args.foreign_sid:
                filtered_lines = []
                lines = output.splitlines()
                idx = 0
                while idx < len(lines):
                    line = lines[idx]
                    if re.match(r'\s+\[ALLOW', line) or re.match(r'\s+\[DENY', line):
                        block = [line]
                        j = idx + 1
                        while j < len(lines) and lines[j].strip() and not re.match(r'\s+\[', lines[j]) and not lines[j].startswith('─') and not lines[j].startswith('═'):
                            block.append(lines[j])
                            j += 1
                        block_text = '\n'.join(block)
                        if args.foreign_sid in block_text:
                            filtered_lines.extend(block)
                            filtered_lines.append('')
                        idx = j
                    else:
                        filtered_lines.append(line)
                        idx += 1

                filtered_output = '\n'.join(filtered_lines)
                if args.foreign_sid not in filtered_output:
                    clean_total += 1
                    if not args.hits_only:
                        print(f"{'─'*70}")
                        print(f"  Object {i_obj}/{len(blobs)}  (no foreign-sid ACEs)")
                        print(f"{'─'*70}\n")
                    continue
                output = filtered_output

            hits_total += 1
            print(f"{'='*70}")
            print(f"  Object {i_obj}/{len(blobs)}  ◄ ATTACK-RELEVANT ACEs")
            print(f"{'='*70}")
            print(output)
        else:
            clean_total += 1
            if not args.hits_only:
                print(f"{'─'*70}")
                print(f"  Object {i_obj}/{len(blobs)}  (clean)")
                print(f"{'─'*70}")
                print(output)

    print(f"\n{'='*70}")
    print(f"  Summary: {hits_total} object(s) with attack-relevant ACEs / {len(blobs)} total")
    print(f"           {clean_total} clean object(s)")
    print(f"{'='*70}\n")


if __name__ == "__main__":
    main()
