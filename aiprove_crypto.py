"""Minimal pure-Python Ethereum crypto for the AiProve sample agent.

Vendored primitives (stdlib only, no third-party deps):
- Keccak-256 (original Keccak padding 0x01, not SHA3's 0x06)
- secp256k1 point arithmetic, RFC 6979 deterministic ECDSA (low-s)
- EIP-191 personal_sign digest, EIP-55 checksummed addresses

Adapted from the muse project's core primitives. The sandbox only needs
python3 — no pip, no npm, no native libs.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

# --------------------------------------------------------------------------
# Keccak-256
# --------------------------------------------------------------------------

_RC = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)

_ROT = (
    (0, 36, 3, 41, 18),
    (1, 44, 10, 45, 2),
    (62, 6, 43, 15, 61),
    (28, 55, 25, 21, 56),
    (27, 20, 39, 8, 14),
)

_MASK = (1 << 64) - 1
_RATE = 136  # bytes


def _rol(value: int, shift: int) -> int:
    if shift == 0:
        return value & _MASK
    return ((value << shift) | (value >> (64 - shift))) & _MASK


def _permute(state: list[int]) -> None:
    for rnd in range(24):
        c = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] ^= d[x]
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rol(state[x + 5 * y], _ROT[x][y])
        for y in range(5):
            for x in range(5):
                state[x + 5 * y] = b[x + 5 * y] ^ ((~b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y])
        state[0] ^= _RC[rnd]


def keccak256(data: bytes) -> bytes:
    """Keccak-256 as used by Ethereum."""
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("keccak256 expects bytes")
    buf = bytearray(data)
    buf.append(0x01)
    while len(buf) % _RATE:
        buf.append(0x00)
    buf[-1] |= 0x80
    state = [0] * 25
    for off in range(0, len(buf), _RATE):
        block = buf[off:off + _RATE]
        for i in range(_RATE // 8):
            state[i] ^= int.from_bytes(block[i * 8:i * 8 + 8], "little")
        _permute(state)
    out = bytearray()
    while len(out) < 32:
        for i in range(_RATE // 8):
            out.extend(state[i].to_bytes(8, "little"))
        if len(out) < 32:
            _permute(state)
    return bytes(out[:32])


# --------------------------------------------------------------------------
# secp256k1
# --------------------------------------------------------------------------

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (GX, GY)


def _inv(value: int, modulus: int) -> int:
    return pow(value % modulus, modulus - 2, modulus)


def point_add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    x1, y1 = a
    x2, y2 = b
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if a == b:
        lam = (3 * x1 * x1) * _inv(2 * y1, P) % P
    else:
        lam = (y2 - y1) * _inv(x2 - x1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    return (x3, (lam * (x1 - x3) - y1) % P)


def point_mul(scalar: int, point=G):
    scalar %= N
    result = None
    addend = point
    while scalar:
        if scalar & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        scalar >>= 1
    return result


def private_to_public(priv: int) -> bytes:
    """Uncompressed 64-byte public key (x || y, no 0x04 prefix)."""
    point = point_mul(priv)
    return point[0].to_bytes(32, "big") + point[1].to_bytes(32, "big")


def _rfc6979_k(priv: int, digest: bytes) -> int:
    x = priv.to_bytes(32, "big")
    h = (int.from_bytes(digest, "big") % N).to_bytes(32, "big")
    v = b"\x01" * 32
    k = b"\x00" * 32
    k = hmac.new(k, v + b"\x00" + x + h, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + x + h, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        candidate = int.from_bytes(v, "big")
        if 1 <= candidate < N:
            return candidate
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


def sign_digest(priv: int, digest: bytes) -> tuple[int, int, int]:
    """Deterministic low-s ECDSA. Returns (r, s, y_parity)."""
    if len(digest) != 32:
        raise ValueError("digest must be 32 bytes")
    z = int.from_bytes(digest, "big")
    nonce = _rfc6979_k(priv, digest)
    point = point_mul(nonce)
    r = point[0] % N
    if r == 0:
        raise ValueError("degenerate nonce")
    s = (_inv(nonce, N) * (z + r * priv)) % N
    if s == 0:
        raise ValueError("degenerate signature")
    parity = point[1] & 1
    if s > N // 2:
        s = N - s
        parity ^= 1
    return r, s, parity


def verify_digest(pub: bytes, digest: bytes, r: int, s: int) -> bool:
    if not (1 <= r < N and 1 <= s < N):
        return False
    x = int.from_bytes(pub[:32], "big")
    y = int.from_bytes(pub[32:], "big")
    if (y * y - x * x * x - 7) % P:
        return False
    z = int.from_bytes(digest, "big")
    w = _inv(s, N)
    point = point_add(point_mul(z * w % N), point_mul(r * w % N, (x, y)))
    return point is not None and point[0] % N == r


# --------------------------------------------------------------------------
# Ethereum addresses + EIP-191 signing
# --------------------------------------------------------------------------

def address_from_priv(priv: int) -> str:
    """EIP-55 checksummed address for a private key."""
    raw = keccak256(private_to_public(priv))[-20:].hex()
    h = keccak256(raw.encode()).hex()
    return "0x" + "".join(c.upper() if int(h[i], 16) >= 8 else c for i, c in enumerate(raw))


def personal_sign(priv: int, message: str) -> str:
    """EIP-191 personal_sign. Returns 0x-prefixed 65-byte signature hex."""
    msg = message.encode()
    digest = keccak256(b"\x19Ethereum Signed Message:\n" + str(len(msg)).encode() + msg)
    r, s, parity = sign_digest(priv, digest)
    assert verify_digest(private_to_public(priv), digest, r, s), "local sig verify failed"
    return "0x" + r.to_bytes(32, "big").hex() + s.to_bytes(32, "big").hex() + bytes([27 + parity]).hex()


def new_private_key() -> int:
    """Fresh random secp256k1 private key."""
    while True:
        k = int.from_bytes(secrets.token_bytes(32), "big")
        if 1 <= k < N:
            return k
