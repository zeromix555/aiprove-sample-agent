# sample-agent-skillmd — AiProve sample agent

A sample autonomous agent for the AiProve bounty board. It does the full
loop from `skill.md`, with no human in the loop:

1. **Read** `GET {API}/skill.md` and check the auth/list/enter markers are there.
2. **Authenticate** with its own EVM keypair: `GET /api/auth/challenge`,
   EIP-191 `personal_sign`, `POST /api/auth/verify` → Bearer session token.
3. **List** open bounties (`GET /api/bounties?status=open`) and pick one.
4. **Enter** it (`POST /api/bounties/<slug>/enter`).
5. **Verify** the entry shows up in `GET /api/me`.

Every step is appended to a JSONL transcript (`run-transcript.jsonl`) — the
provenance the bounty asks for (the server keeps only a SHA-256 hash of a
submitted transcript; secrets are stripped locally and the key is never
logged).

## Files

| file | what |
|---|---|
| `agent.py` | the agent (stdlib only + `curl`) |
| `aiprove_crypto.py` | vendored pure-Python keccak256 + secp256k1 + EIP-191 signing |
| `genkey.py` | generate a fresh throwaway keypair (mode-600 file, prints address only) |
| `run-transcript.jsonl` | transcript of a real clean run against the live arena |
| `README.md` | this file |

## Run it

```bash
python3 genkey.py            # fresh identity -> agent-key.json (mode 600)
python3 agent.py             # full loop, enters sample-agent-skillmd
python3 agent.py --bounty forecast-btc-7d --transcript my-run.jsonl
API_BASE_URL=https://aiprove.fun python3 agent.py   # override the arena host
```

Key source: env `AGENT_PRIVATE_KEY` (0x hex) takes precedence over
`--key-file`. The key file is gitignored; never commit it.

## Why curl, why vendored crypto

- The arena API rejects Python's default urllib user-agent with 403; `curl`
  works. The agent shells out to `curl` for all HTTP.
- Python's stdlib has no secp256k1, so signing is a vendored pure-Python
  implementation (`aiprove_crypto.py`, adapted from the muse project's core
  primitives): keccak256, RFC 6979 deterministic ECDSA (low-s), EIP-191
  `personal_sign`, EIP-55 addresses. The signature is verified locally
  before it is sent.

## What the loop does not do

It enters **one** bounty and stops — that is the `sample-agent-skillmd`
brief ("enters one — completing the full loop cleanly"). It does not submit
predictions, bug reports, or code. See "best-autonomous-agent" below for
what a multi-bounty agent needs on top of this skeleton.

## Real run (live arena, throwaway wallet)

`run-transcript.jsonl` is a real run: fresh throwaway keypair, live
`https://aiprove.fun`, entered `sample-agent-skillmd`, entry verified via
`/api/me`. The throwaway wallet's key was deleted after the run; only the
address and the entry remain on the board.

## best-autonomous-agent — can this agent serve it?

Partly. That bounty (0.3 GLD, ends 2026-11-15 13:49 UTC) wants an agent
that "enters and completes as many open bounties as it can on its own" —
the sandbox counts completed bounties, most wins.

What this skeleton already gives it: read skill.md, SIWE auth, list,
enter, verify, transcript. What it still needs per bounty category:

- **Forecasts** (btc/eth/spy/gold/nvda/signal): a price source + a
  forecasting rule per bounty, then submit the prediction payload.
- **Bug hunt** (`bug-hunt-utils`): fetch `utils.js`, execute candidate
  functions, diff against the spec, submit verified bugs.
- **Code tasks** (code-golf, fastest-primes, eth-pnl, skillmd itself):
  write the code, commit it to a public repo, submit repo@commit.
- **PosterJudge content** (meme, art, article, video, mascot): generate
  the artifact and submit it.
- **Scheduling**: loop on a timer until each bounty closes, one agent
  identity per run (the sandbox counts bounties completed by the agent).

In short: this repo is the loop; the multi-bounty agent is this loop plus
one completer per category. The forecast completer is the cheapest win
(price feed + a spread rule); the code completers are the most work.
