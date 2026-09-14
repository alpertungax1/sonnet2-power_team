# /// script
# requires-python = ">=3.12"
# dependencies = ["cryptography"]
# ///
"""Standalone Auto-Submitter for banki358 (power_team in sonnet-2).

Usage:
  export BANKI_SEED="<your 64-hex seed or passphrase>"
  uv run banki358_worker.py

Or pass seed directly:
  uv run banki358_worker.py --seed <SEED>

Runs continuously in the background. Polls room receipts every 10 seconds.
When your turn arrives, it immediately signs and submits your assigned word.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
import time
import unicodedata
import urllib.request
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

CONTEST_ID = "sonnet-2"
GAME_ID = "power_team"
TEAM_ROOM = f"d-{CONTEST_ID}-team-{GAME_ID}"
BASE_URL = "https://technocore.chat"

# banki358's exact 33 assigned words across the 121-word sonnet
BANKI_WORDS: dict[int, str] = {
    0: "the",
    4: "doth",
    7: "sum",
    12: "the",
    15: "sorrow",
    20: "pure",
    23: "doth",
    32: "tender",
    34: "do",
    37: "tender",
    39: "doth",
    44: "where",
    46: "doth",
    48: "to",
    52: "view",
    54: "grief",
    59: "my",
    63: "we",
    66: "trust",
    68: "true",
    70: "pure",
    73: "doth",
    76: "comfort",
    78: "to",
    81: "the",
    87: "sweet",
    90: "of",
    92: "we",
    94: "to",
    104: "so",
    107: "truth",
    115: "joy",
    118: "sweet",
}

B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
MULTICODEC_ED25519 = b"\xed\x01"

def b58encode(b: bytes) -> str:
    n = int.from_bytes(b, "big")
    chars = []
    while n > 0:
        n, r = divmod(n, 58)
        chars.append(B58_ALPHABET[r])
    chars.reverse()
    pad = 0
    for byte in b:
        if byte == 0:
            pad += 1
        else:
            break
    return "1" * pad + "".join(chars)

def did_of(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes_raw()
    return "did:key:z" + b58encode(MULTICODEC_ED25519 + raw)

def swept(s: str, max_chars: int) -> str:
    cleaned = "".join(" " if unicodedata.category(c) in {"Cc", "Cf", "Cs", "Co", "Zl", "Zp"} else c for c in s).strip()
    return cleaned[:max_chars]

def signature(key: Ed25519PrivateKey, canonical: str) -> str:
    sig = key.sign(canonical.encode("utf-8"))
    return base64.urlsafe_b64encode(sig).rstrip(b"=").decode("ascii")

def load_key(seed_str: str) -> Ed25519PrivateKey:
    s = seed_str.strip()
    if len(s) == 64:
        try:
            seed_bytes = bytes.fromhex(s)
        except ValueError:
            seed_bytes = hashlib.sha256(s.encode("utf-8")).digest()
    else:
        seed_bytes = hashlib.sha256(s.encode("utf-8")).digest()
    return Ed25519PrivateKey.from_private_bytes(seed_bytes)

def fetch_latest_receipt() -> tuple[int, str, str, bool] | None:
    """Returns (version, state_hash, sender_did, complete) from newest accepted receipt."""
    url = f"{BASE_URL}/r/{TEAM_ROOM}/export"
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (banki-worker)"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        lines = resp.read().decode("utf-8").strip().split("\n")
    for line in reversed(lines):
        if not line.strip():
            continue
        try:
            msg = json.loads(line)
            text = json.loads(msg.get("text", "{}"))
            if text.get("type") == "sonnet.receipt.v1" and text.get("status") == "accepted":
                return (
                    int(text.get("version", 0)),
                    str(text.get("state_hash", "")),
                    str(text.get("sender_did", "")),
                    bool(text.get("complete", False))
                )
        except Exception:
            continue
    return None

def submit_word(key: Ed25519PrivateKey, did: str, version: int, state_hash: str, word: str) -> bool:
    req_id = f"banki-w{version}-{int(time.time())}"
    payload = {
        "type": "sonnet.word.v1",
        "contest_id": CONTEST_ID,
        "game_id": GAME_ID,
        "room_generation": 1,
        "version": version,
        "previous_state_hash": state_hash,
        "word": word,
        "request_id": req_id
    }
    text = json.dumps(payload, separators=(',', ':'))
    nonce = str(int(time.time() * 1000))
    canonical = f"{TEAM_ROOM}|{nonce}|{swept(text, 4096)}"
    sig = signature(key, canonical)

    body = json.dumps({
        "did": did,
        "sig": sig,
        "nonce": nonce,
        "text": text
    }).encode("utf-8")

    url = f"{BASE_URL}/r/{TEAM_ROOM}"
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0 (banki-worker)"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            print(f"[SUBMIT OK] Version {version} ('{word}') submitted! Response: {resp.read().decode('utf-8')}")
            return True
    except Exception as e:
        print(f"[SUBMIT ERROR] Failed to submit word {version}: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description="banki358 auto submitter for power_team")
    parser.add_argument("--seed", default=os.getenv("BANKI_SEED"), help="64-hex seed or passphrase")
    parser.add_argument("--dry-run", action="store_true", help="Check state and exit without submitting")
    args = parser.parse_args()

    if not args.seed:
        print("ERROR: Please provide seed via --seed or BANKI_SEED environment variable.")
        sys.exit(1)

    key = load_key(args.seed)
    my_did = did_of(key)
    print(f"Loaded identity: {my_did}")
    if my_did != "did:key:z6Mkr3iQCJcWujP9DV9MBbN1qnFUnWhiJ5sQgCcjodTJMYEF":
        print(f"WARNING: Your DID ({my_did}) differs from banki358 DID (did:key:z6Mkr3iQCJcWujP9DV9MBbN1qnFUnWhiJ5sQgCcjodTJMYEF).")

    print(f"Monitoring room {TEAM_ROOM} for banki358's turns (33 assigned words)...")

    while True:
        try:
            info = fetch_latest_receipt()
            if not info:
                print("No accepted receipts found yet, waiting...")
            else:
                curr_version, state_hash, last_sender, complete = info
                if complete:
                    print(f"Poem is complete at version {curr_version}! Worker exiting successfully.")
                    break

                if curr_version in BANKI_WORDS:
                    target_word = BANKI_WORDS[curr_version]
                    if last_sender == my_did:
                        print(f"Version {curr_version} was already submitted by us. Waiting for next member...")
                    else:
                        print(f"--> IT IS YOUR TURN! Version: {curr_version}, Word: '{target_word}', State Hash: {state_hash}")
                        if args.dry_run:
                            print("[DRY RUN] Would submit now. Exiting.")
                            break
                        submit_word(key, my_did, curr_version, state_hash, target_word)
                else:
                    print(f"Current version is {curr_version} (waiting for other teammate, next banki turn is >= {curr_version})...")
        except Exception as err:
            print(f"Error during poll: {err}")

        if args.dry_run:
            break
        time.sleep(10)

if __name__ == "__main__":
    main()
