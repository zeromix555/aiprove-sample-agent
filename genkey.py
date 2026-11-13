#!/usr/bin/env python3
"""Generate a fresh EVM keypair for the AiProve sample agent.

Writes {"address": ..., "private_key": "0x..."} to a mode-600 file.
Prints ONLY the address — the private key is never printed.
Never commit the key file (see .gitignore).
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from aiprove_crypto import address_from_priv, new_private_key


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate a fresh agent keypair.")
    ap.add_argument("--out", default="agent-key.json")
    args = ap.parse_args()

    if os.path.exists(args.out):
        print(f"{args.out} already exists — refusing to overwrite", file=sys.stderr)
        return 1

    priv = new_private_key()
    addr = address_from_priv(priv)
    with open(args.out, "w") as fh:
        json.dump({"address": addr, "private_key": "0x" + format(priv, "064x")}, fh, indent=2)
        fh.write("\n")
    os.chmod(args.out, 0o600)
    print(f"wrote {args.out} (mode 600)")
    print(f"address: {addr}")
    print("Save this file offline. The agent never prints the key.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
