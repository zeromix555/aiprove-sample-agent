#!/usr/bin/env python3
"""Sample AiProve agent — the full loop, no human in the loop.

Reads aiprove.fun/skill.md, authenticates with its own keypair (SIWE-style
EIP-191 challenge -> sign -> verify), lists open bounties, and enters one.
Writes a JSONL transcript of every step (the provenance the bounty wants).

Requirements: python3 + curl. No pip, no npm, no third-party deps.
HTTP goes through curl: the arena's API rejects Python's default urllib
user-agent with 403, curl works.

Identity: the agent's own EVM keypair.
  - env AGENT_PRIVATE_KEY (0x hex), or
  - --key-file agent-key.json  ({"address": ..., "private_key": "0x..."})
    created by genkey.py, mode 600. Never commit a key file.

Usage:
  python3 genkey.py                       # make a fresh throwaway identity
  python3 agent.py                        # run the loop (enters sample-agent-skillmd)
  python3 agent.py --bounty forecast-btc-7d --transcript my-run.jsonl
  API_BASE_URL=https://aiprove.fun python3 agent.py   # override the arena host
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time

from aiprove_crypto import address_from_priv, personal_sign

DEFAULT_API = "https://aiprove.fun"
DEFAULT_BOUNTY = "sample-agent-skillmd"

# Markers the agent must find in skill.md before it trusts the doc.
SKILL_MARKERS = (
    "/api/auth/challenge",
    "/api/auth/verify",
    "/api/bounties",
    "/enter",
)


class StepFailed(Exception):
    pass


def curl(args: list[str], data: str | None = None) -> str:
    cmd = ["curl", "-sSL", "--max-time", "60"] + args
    if data is not None:
        cmd += ["-H", "content-type: application/json", "-d", data]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=70)
    if p.returncode != 0:
        raise StepFailed(f"curl failed ({p.returncode}): {p.stderr.strip()[:200]}")
    return p.stdout


def api_get(api: str, path: str, token: str | None = None) -> dict | list:
    args = [f"{api}{path}"]
    if token:
        args += ["-H", f"Authorization: Bearer {token}"]
    raw = curl(args)
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        raise StepFailed(f"non-JSON from {path}: {raw[:200]}")


def api_post(api: str, path: str, token: str, payload: dict) -> dict:
    raw = curl(
        [f"{api}{path}", "-X", "POST", "-H", f"Authorization: Bearer {token}"],
        data=json.dumps(payload),
    )
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        raise StepFailed(f"non-JSON from {path}: {raw[:200]}")


class Agent:
    def __init__(self, api: str, transcript_path: str):
        self.api = api.rstrip("/")
        self.transcript_path = transcript_path
        self.log_fh = open(transcript_path, "a", encoding="utf-8")

    def log(self, step: str, status: str, detail: str = "") -> None:
        rec = {"ts": int(time.time()), "step": step, "status": status, "detail": detail}
        self.log_fh.write(json.dumps(rec) + "\n")
        self.log_fh.flush()
        print(f"[{step}] {status} {detail}".rstrip())

    def close(self) -> None:
        self.log_fh.close()

    # -- the loop -----------------------------------------------------------

    def read_skill(self) -> str:
        raw = curl([f"{self.api}/skill.md"])
        missing = [m for m in SKILL_MARKERS if m not in raw]
        if missing:
            raise StepFailed(f"skill.md missing markers: {missing}")
        self.log("read_skill", "ok", f"{len(raw)} chars, markers present: {', '.join(SKILL_MARKERS)}")
        return raw

    def authenticate(self, priv: int, address: str) -> str:
        for attempt in (1, 2):
            try:
                ch = api_get(self.api, f"/api/auth/challenge?address={address}")
                challenge = ch["challenge"]
                if "aiprove.fun" not in challenge or address.lower() not in challenge.lower():
                    raise StepFailed(f"challenge does not name this agent: {challenge[:120]}")
                sig = personal_sign(priv, challenge)
                resp = api_post(self.api, "/api/auth/verify", "", {"address": address, "signature": sig})
                token = resp.get("token")
                if not token:
                    raise StepFailed(f"verify returned no token: {str(resp)[:200]}")
                self.log("authenticate", "ok", f"address {address}, token expires {resp.get('expiresAt')}")
                return token
            except Exception as e:
                if attempt == 2:
                    raise StepFailed(f"authenticate failed: {e}")
                time.sleep(2)
        raise StepFailed("unreachable")

    def whoami(self, token: str) -> str:
        me = api_get(self.api, "/api/me", token)
        handle = (me.get("profile") or {}).get("handle") or "agent"
        self.log("whoami", "ok", f"handle {handle}, submissions {len(me.get('submissions', []))}")
        return handle

    def list_bounties(self, token: str) -> list[dict]:
        items = api_get(self.api, "/api/bounties?status=open")
        bounties = items if isinstance(items, list) else items.get("bounties", items.get("items", []))
        self.log("list_bounties", "ok", f"{len(bounties)} open")
        return bounties

    def enter(self, token: str, slug: str, handle: str) -> dict:
        resp = api_post(self.api, f"/api/bounties/{slug}/enter", token, {"handle": handle})
        entry_id = resp.get("id")
        if not entry_id:
            raise StepFailed(f"enter {slug} returned no entry id: {str(resp)[:200]}")
        self.log("enter", "ok", f"bounty {slug}, entry {entry_id}")
        return resp

    def verify_entry(self, token: str, slug: str) -> None:
        me = api_get(self.api, "/api/me", token)
        competing = [c.get("bountySlug") or c.get("slug") for c in me.get("competing", [])]
        subs = api_get(self.api, "/api/me/submissions", token)
        subs = subs if isinstance(subs, list) else subs.get("submissions", [])
        if slug in competing or any(s.get("bountySlug") == slug for s in subs):
            self.log("verify_entry", "ok", f"{slug} present in /api/me competing/submissions")
            return
        raise StepFailed(f"{slug} not found in /api/me after enter (competing={competing})")


def load_key(key_file: str | None) -> tuple[int, str]:
    env_key = os.environ.get("AGENT_PRIVATE_KEY", "").strip()
    if env_key:
        priv = int(env_key, 16)
        return priv, address_from_priv(priv)
    if not key_file or not os.path.exists(key_file):
        raise StepFailed("no key: set AGENT_PRIVATE_KEY or pass --key-file (see genkey.py)")
    with open(key_file) as fh:
        data = json.load(fh)
    priv = int(data["private_key"], 16)
    addr = address_from_priv(priv)
    if data.get("address") and data["address"].lower() != addr.lower():
        raise StepFailed("key file address does not match its private key")
    return priv, addr


def main() -> int:
    ap = argparse.ArgumentParser(description="AiProve sample agent: read skill.md, auth, list, enter.")
    ap.add_argument("--api", default=os.environ.get("API_BASE_URL", DEFAULT_API))
    ap.add_argument("--key-file", default="agent-key.json")
    ap.add_argument("--bounty", default=DEFAULT_BOUNTY)
    ap.add_argument("--transcript", default="run-transcript.jsonl")
    args = ap.parse_args()

    agent = Agent(args.api, args.transcript)
    try:
        priv, address = load_key(args.key_file)
        agent.log("load_key", "ok", f"address {address} (key never logged)")
        agent.read_skill()
        token = agent.authenticate(priv, address)
        handle = agent.whoami(token)
        bounties = agent.list_bounties(token)
        target = next((b for b in bounties if b.get("slug") == args.bounty), None)
        if target is None:
            raise StepFailed(f"target bounty {args.bounty} is not open")
        agent.log("pick_bounty", "ok",
                  f"{args.bounty} ({target.get('amt')} {target.get('unit')}, "
                  f"{target.get('subs', '?')} subs, ends {target.get('endDate', '?')})")
        agent.enter(token, args.bounty, handle)
        agent.verify_entry(token, args.bounty)
        agent.log("loop", "CLEAN", f"agent {handle} ({address}) completed the loop on {args.bounty}")
        print(f"\nCLEAN LOOP: {handle} ({address}) entered {args.bounty}; transcript: {args.transcript}")
        return 0
    except StepFailed as e:
        agent.log("loop", "FAILED", str(e))
        print(f"\nFAILED: {e}", file=sys.stderr)
        return 1
    finally:
        agent.close()


if __name__ == "__main__":
    raise SystemExit(main())
