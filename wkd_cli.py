#!/usr/bin/env python3
"""
wkd-cli — Command-line tool for managing WKD key store.

Operates directly on the cache directory — no server required.
Run as the same user that owns the cache_dir (or as root).

Usage:
  wkd-cli publish  --email <email> --key <file.asc|file.gpg>
  wkd-cli revoke   --email <email>
  wkd-cli list     [--domain <domain>]
  wkd-cli show     --email <email>
  wkd-cli hash     --email <email>

Config is loaded from WKD_CONFIG env var (default: /opt/encedo-wkd/config.json).
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

import config as cfg
import store
from wkd import wkd_hash, extract_uids


# ------------------------------------------------------------------ commands

def cmd_publish(args) -> int:
    email = args.email.strip().lower()
    key_path = args.key

    if not os.path.isfile(key_path):
        print(f"error: key file not found: {key_path}", file=sys.stderr)
        return 1

    with open(key_path, "rb") as f:
        raw = f.read()

    # Accept ASCII-armored or binary
    pubkey_bytes = _decode_key(raw)
    if pubkey_bytes is None:
        print("error: could not decode key (expected binary OpenPGP or ASCII-armored)", file=sys.stderr)
        return 1

    uids = extract_uids(pubkey_bytes)
    if not any(email in uid.lower() for uid in uids):
        print(f"error: key does not contain a User ID matching {email}", file=sys.stderr)
        print(f"  UIDs in key: {uids}", file=sys.stderr)
        return 1

    local, domain = email.split("@", 1)
    hash_ = wkd_hash(local)
    store.put_key(domain, hash_, pubkey_bytes)
    print(f"published: {email}")
    print(f"  domain : {domain}")
    print(f"  hash   : {hash_}")
    print(f"  uids   : {', '.join(uids)}")
    return 0


def cmd_revoke(args) -> int:
    email = args.email.strip().lower()
    local, domain = email.split("@", 1)
    hash_ = wkd_hash(local)
    deleted = store.delete_key(domain, hash_)
    if deleted:
        print(f"revoked: {email} (hash={hash_})")
        return 0
    else:
        print(f"not found: {email} (hash={hash_})")
        return 1


def cmd_list(args) -> int:
    cache_dir = store._cache_dir
    if not os.path.isdir(cache_dir):
        print(f"cache_dir does not exist: {cache_dir}", file=sys.stderr)
        return 1

    filter_domain = args.domain.strip().lower() if args.domain else None
    found = 0

    domains = sorted(os.listdir(cache_dir))
    for domain in domains:
        domain_path = os.path.join(cache_dir, domain)
        if not os.path.isdir(domain_path):
            continue
        if filter_domain and domain != filter_domain:
            continue
        for hash_ in sorted(os.listdir(domain_path)):
            key_path = os.path.join(domain_path, hash_)
            if not os.path.isfile(key_path):
                continue
            size = os.path.getsize(key_path)
            try:
                with open(key_path, "rb") as f:
                    data = f.read()
                uids = extract_uids(data)
                uid_str = ", ".join(uids) if uids else "(unknown)"
            except Exception:
                uid_str = "(error reading UIDs)"
            print(f"{domain:30s}  {hash_}  {size:6d}B  {uid_str}")
            found += 1

    if found == 0:
        print("(no keys found)")
    return 0


def cmd_show(args) -> int:
    email = args.email.strip().lower()
    local, domain = email.split("@", 1)
    hash_ = wkd_hash(local)
    data = store.get_key(domain, hash_)
    if data is None:
        print(f"not found: {email}")
        return 1
    uids = extract_uids(data)
    print(f"email  : {email}")
    print(f"domain : {domain}")
    print(f"hash   : {hash_}")
    print(f"size   : {len(data)} bytes")
    print(f"uids   : {', '.join(uids) if uids else '(none)'}")
    return 0


def cmd_hash(args) -> int:
    email = args.email.strip().lower()
    if "@" not in email:
        print(f"error: not a valid email: {email}", file=sys.stderr)
        return 1
    local, domain = email.split("@", 1)
    hash_ = wkd_hash(local)
    print(f"{hash_}  ({email})")
    return 0


# ------------------------------------------------------------------ helpers

def _decode_key(raw: bytes) -> bytes | None:
    """Return binary OpenPGP from either binary or ASCII-armored input."""
    if raw[:1] == b"\x99" or raw[:1] == b"\xc5" or (raw[:1][0] & 0x80):
        # Looks like binary OpenPGP packet
        return raw
    # Try ASCII armor
    text = raw.decode("ascii", errors="ignore")
    if "-----BEGIN PGP PUBLIC KEY BLOCK-----" in text:
        import base64
        lines = text.splitlines()
        in_body = False
        b64_lines = []
        for line in lines:
            if line.startswith("-----BEGIN"):
                in_body = True
                continue
            if line.startswith("-----END"):
                break
            if in_body:
                if line.startswith("="):
                    break  # checksum line
                if line.strip():
                    b64_lines.append(line.strip())
        # skip blank separator line after headers
        try:
            idx = next(i for i, l in enumerate(b64_lines) if l == "")
            b64_lines = b64_lines[idx + 1:]
        except StopIteration:
            pass
        try:
            return base64.b64decode("".join(b64_lines))
        except Exception:
            return None
    return None


# ------------------------------------------------------------------ main

def main():
    parser = argparse.ArgumentParser(
        prog="wkd-cli",
        description="Manage the WKD key store directly (no server required).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_pub = sub.add_parser("publish", help="Publish a public key")
    p_pub.add_argument("--email", required=True, help="Email address")
    p_pub.add_argument("--key", required=True, metavar="FILE", help="Public key file (binary or armored)")

    p_rev = sub.add_parser("revoke", help="Remove a public key")
    p_rev.add_argument("--email", required=True, help="Email address")

    p_list = sub.add_parser("list", help="List all stored keys")
    p_list.add_argument("--domain", default=None, help="Filter by domain")

    p_show = sub.add_parser("show", help="Show key details for an email")
    p_show.add_argument("--email", required=True, help="Email address")

    p_hash = sub.add_parser("hash", help="Print the WKD hash for an email")
    p_hash.add_argument("--email", required=True, help="Email address")

    args = parser.parse_args()

    # Load config (for cache_dir)
    config = cfg.load_config()
    store.init(config["cache_dir"])

    commands = {
        "publish": cmd_publish,
        "revoke":  cmd_revoke,
        "list":    cmd_list,
        "show":    cmd_show,
        "hash":    cmd_hash,
    }
    sys.exit(commands[args.command](args))


if __name__ == "__main__":
    main()
