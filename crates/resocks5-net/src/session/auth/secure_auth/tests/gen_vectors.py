#!/usr/bin/env python3
"""Known-answer vectors for secure-auth (`vectors.rs`).

Computed with Python's `cryptography` package from the documented wire
format (see `secure_auth/mod.rs` and `init.rs`), never from the Rust code, so
the expected values are an independent oracle. Run:

    python3 -I gen_vectors.py

and paste the output into `vectors.rs` only if the protocol itself changes
(a dependency bump must never change a single byte).
"""

import hashlib
import hmac
import struct

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

PASSWORD = b"correct horse battery staple"
SALT = bytes(range(16))
USER = b"alice"
CNONCE = bytes(range(0x20, 0x40))
SNONCE = bytes(range(0x40, 0x60))


def kdf(m, t, p):
    return Argon2id(
        salt=SALT, length=32, iterations=t, lanes=p, memory_cost=m
    ).derive(PASSWORD)


def params(m, t, p):
    return struct.pack(">IBB", m, t, p)


def out(name, value):
    print(f"{name} = {value.hex()}")


for m, t, p in [(8, 1, 1), (64, 1, 1), (64, 2, 2), (19456, 2, 1)]:
    out(f"argon2id m={m} t={t} p={p}", kdf(m, t, p))

K = kdf(64, 1, 1)
P = params(64, 1, 1)
out("params 64/1/1", P)
out("params 19456/2/1", params(19456, 2, 1))

client = hmac.new(
    K,
    b"resocks5-secure/1 client"
    + bytes([len(USER)]) + USER
    + SNONCE + CNONCE
    + bytes([len(SALT)]) + SALT
    + P,
    hashlib.sha256,
).digest()
out("client_proof", client)

server = hmac.new(
    K,
    b"resocks5-secure/1 server" + bytes([len(USER)]) + USER + CNONCE + SNONCE,
    hashlib.sha256,
).digest()
out("server_proof", server)

# Decoy answers for an unknown user: HMAC(decoy_key, label | user).
DECOY_KEY = bytes([7]) * 32
out("decoy salt (first 16)", hmac.new(DECOY_KEY, b"decoy salt" + USER, hashlib.sha256).digest()[:16])
out("decoy key", hmac.new(DECOY_KEY, b"decoy key" + USER, hashlib.sha256).digest())

# X25519 with fixed private keys (clamping is done by the library).
a_priv = bytes(range(1, 33))
b_priv = bytes(range(33, 65))
a = X25519PrivateKey.from_private_bytes(a_priv)
b = X25519PrivateKey.from_private_bytes(b_priv)
raw = lambda pub: pub.public_bytes_raw()
out("x25519 a_priv", a_priv)
out("x25519 b_priv", b_priv)
out("x25519 a_pub", raw(a.public_key()))
out("x25519 b_pub", raw(b.public_key()))
shared = a.exchange(b.public_key())
assert shared == b.exchange(a.public_key())
out("x25519 shared", shared)

# init: AEAD key = HKDF-SHA256(salt = label, ikm = shared, info = transcript).
LABEL = b"resocks5-secure/1 init"
a_pub = raw(a.public_key())
b_pub = raw(b.public_key())
info = bytes([len(USER)]) + USER + CNONCE + SNONCE + a_pub + b_pub
aead_key = HKDF(
    algorithm=hashes.SHA256(), length=32, salt=LABEL, info=info
).derive(shared)
out("init aead_key", aead_key)

plain = bytes([len(SALT)]) + SALT + P + K
aad = LABEL + bytes([len(USER)]) + USER + CNONCE + SNONCE
sealed = ChaCha20Poly1305(aead_key).encrypt(b"\x00" * 12, plain, aad)
out("init sealed", sealed)
