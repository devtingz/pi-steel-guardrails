#!/usr/bin/env python3
"""
authorizer_override.py — Compute HMAC-SHA256 override for tool-authorizer.

Usage:
    python authorizer_override.py <secret_file> <denial_uuid> <tool_name>

    <secret_file> : path to the authorizer secret file
                    (default: ~/.pi/secret/authorizer-secret.txt)
    <denial_uuid> : the UUID from the AUTHORIZER_DENIED reason
    <tool_name>   : the tool that was denied (e.g. read, bash, write)

Example:
    python authorizer_override.py \\
        ~/.pi/secret/authorizer-secret.txt \\
        ebb19bed-aa06-48b3-be52-d31e9087fb84 \\
        read

The output is a 64-character hex MAC. Pass it to the approve_override
Pi Agent tool via:
    approve_override(denial_uuid="...", mac="<output>")

After a successful override, the shared secret rotates (version increments),
so re-read the file for subsequent overrides.
"""

import sys
import os
import hashlib
import hmac
import re


def parse_secret(filepath: str) -> tuple[int, str]:
    """Parse 'v=<version>;secret=<64hex>' from file, return (version, raw_hex)."""
    with open(filepath, "r") as f:
        raw = f.read().strip()

    v_match = re.search(r"v=(\d+);", raw)
    s_match = re.search(r"secret=([a-fA-F0-9]{64})", raw)
    if not v_match or not s_match:
        print("Error: Invalid secret file format. Expected 'v=<N>;secret=<64hex>'")
        sys.exit(1)

    return int(v_match.group(1)), s_match.group(1).lower()


def compute_mac(secret_hex: str, denial_uuid: str, tool_name: str) -> str:
    """Compute HMAC-SHA256(secret_hex as UTF-8, 'denial_uuid:tool_name').

    The hex string is passed as-is (64 UTF-8 bytes) to match Node.js
    crypto.createHmac('sha256', secretHexString) behavior, NOT hex-decoded.
    """
    # NOTE: Node.js createHmac(algorithm, key) treats a string key as UTF-8 bytes,
    # so we pass the hex string as-is (64 ASCII bytes), NOT hex-decoded (32 raw bytes).
    key = secret_hex.encode("utf-8")
    data = f"{denial_uuid}:{tool_name}".encode("utf-8")
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)

    secret_file = sys.argv[1]
    denial_uuid = sys.argv[2]
    tool_name = sys.argv[3] if len(sys.argv) >= 4 else input("Tool name: ")

    # Expand ~ to user home directory
    secret_file = os.path.expanduser(secret_file)

    if not os.path.isfile(secret_file):
        print(f"Error: Secret file not found: {secret_file}")
        sys.exit(1)

    version, secret_hex = parse_secret(secret_file)
    mac = compute_mac(secret_hex, denial_uuid, tool_name)

    data_check = f'"{denial_uuid}:{tool_name}"'
    print(f"Secret file : {secret_file}")
    print(f"Secret ver  : {version}")
    print(f"Data        : HMAC-SHA256({secret_hex[:8]}...{secret_hex[-8:]}, {data_check})")
    print(f"MAC         : {mac}")
    print(f"Prompt      : Use the approve_override tool -- the Denial UUID is {denial_uuid} and the MAC is {mac}")


if __name__ == "__main__":
    main()
