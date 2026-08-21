#!/usr/bin/env python3
"""
Build the encrypted itinerary payload for GitHub Pages.

    python3 build.py                      # uses "passphrase" from source/config.json
    python3 build.py --passphrase "..."   # or override it for one build

Reads   : source/itinerary.html   (the plain itinerary, never committed)
          source/config.json      (your Supabase keys, never committed)
Writes  : index.html              (the shell, safe to commit)
          payload.json            (AES-256-GCM ciphertext, safe to commit)

The passphrase is stretched with PBKDF2-HMAC-SHA256 (300,000 iterations) and the
payload is sealed with AES-256-GCM. Without the passphrase, payload.json is noise.
"""

import argparse
import base64
import json
import os
import re
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Placeholder only. The real passphrase lives in source/config.json, which is
# gitignored. Never put the real passphrase here: build.py is committed, and a
# public repo would then publish the key next to the payload it decrypts.
PLACEHOLDER_PASSPHRASE = "dogsbay"
ITERATIONS = 300_000

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "source")


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def derive(passphrase: str, salt: bytes) -> bytes:
    return PBKDF2HMAC(
        algorithm=SHA256(), length=32, salt=salt, iterations=ITERATIONS
    ).derive(passphrase.encode("utf-8"))


def split_source(html: str):
    """Return (css_block, body_html) from the designed itinerary file."""
    marker = "</style>"
    if marker not in html:
        sys.exit("itinerary.html has no <style> block. Is it the right file?")
    head, body = html.split(marker, 1)
    css = head[head.index("<style>") + len("<style>"):]
    return css.strip(), body.strip()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--passphrase", default=None)
    args = ap.parse_args()

    src_path = os.path.join(SRC, "itinerary.html")
    if not os.path.exists(src_path):
        sys.exit(f"Missing {src_path}")

    with open(src_path, encoding="utf-8") as fh:
        css, body = split_source(fh.read())

    cfg_path = os.path.join(SRC, "config.json")
    config = {"supabaseUrl": "", "supabaseAnonKey": ""}
    if os.path.exists(cfg_path):
        with open(cfg_path, encoding="utf-8") as fh:
            config.update(json.load(fh))

    passphrase = args.passphrase or config.get("passphrase") or ""
    if not passphrase:
        sys.exit(
            'No passphrase. Add a "passphrase" key to source/config.json, '
            "or pass --passphrase for a one-off build."
        )
    if passphrase == PLACEHOLDER_PASSPHRASE:
        sys.exit(
            f"Refusing to build with the placeholder passphrase "
            f"{PLACEHOLDER_PASSPHRASE!r}. Set a real one in source/config.json."
        )

    plaintext = json.dumps(
        {
            "html": body,
            "supabaseUrl": config["supabaseUrl"].rstrip("/"),
            "supabaseAnonKey": config["supabaseAnonKey"],
        },
        ensure_ascii=False,
    ).encode("utf-8")

    salt = os.urandom(16)
    iv = os.urandom(12)
    key = derive(passphrase, salt)
    sealed = AESGCM(key).encrypt(iv, plaintext, None)

    with open(os.path.join(HERE, "payload.json"), "w", encoding="utf-8") as fh:
        json.dump(
            {"v": 1, "kdf": "PBKDF2-SHA256", "iterations": ITERATIONS,
             "salt": b64(salt), "iv": b64(iv), "data": b64(sealed)},
            fh,
        )

    shell_path = os.path.join(HERE, "shell.html")
    with open(shell_path, encoding="utf-8") as fh:
        shell = fh.read()
    shell = shell.replace("/*__ITINERARY_CSS__*/", css)
    with open(os.path.join(HERE, "index.html"), "w", encoding="utf-8") as fh:
        fh.write(shell)

    has_keys = bool(config["supabaseUrl"] and config["supabaseAnonKey"])
    print(f"payload.json  {len(sealed) / 1024:.0f} KB sealed")
    print(f"index.html    written")
    print(f"passphrase    {passphrase!r}")
    print(f"comments      {'configured' if has_keys else 'NOT configured, see README step 2'}")


if __name__ == "__main__":
    main()
