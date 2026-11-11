//! Known-answer tests: every byte secure-auth puts on the wire or stores is
//! pinned to values computed by an independent implementation
//! (`gen_vectors.py`, Python `cryptography`, from the documented format). A
//! dependency upgrade (hmac, sha2, hkdf, x25519, chacha20poly1305, argon2,
//! getrandom) must keep every one of these passing unchanged.

use std::collections::HashMap;
use std::sync::Mutex;

use hmac::{Hmac, Mac};
use sha2::Sha256;
use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

use super::super::init::{open, seal, Transcript, PUBLIC_LEN};
use super::super::kdf::{derive_key, KdfParams, UserSecret, KEY_LEN};
use super::super::wire::{client_proof, encode_params, server_proof, NONCE_LEN, PROOF_LEN};
use super::super::{server_authenticate, DecoyKey, DerivationLimiter, SecretStore, StoredUser};

const PASSWORD: &[u8] = b"correct horse battery staple";
const USER: &[u8] = b"alice";
const WEAK: KdfParams = KdfParams {
    memory_kib: 64,
    iterations: 1,
    parallelism: 1,
};

fn hex<const N: usize>(s: &str) -> [u8; N] {
    let bytes: Vec<u8> = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect();
    bytes.try_into().expect("vector length")
}

fn hex_vec(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn salt() -> [u8; 16] {
    std::array::from_fn(|i| u8::try_from(i).unwrap())
}

fn cnonce() -> [u8; NONCE_LEN] {
    std::array::from_fn(|i| 0x20 + u8::try_from(i).unwrap())
}

fn snonce() -> [u8; NONCE_LEN] {
    std::array::from_fn(|i| 0x40 + u8::try_from(i).unwrap())
}

const K_64_1_1: &str = "92dc5d67019623868bde079275e522f4b7e8213d3414ed85cbc2ac8a41117288";

/// Argon2id (version 0x13, 32-byte tag) for the costs a secret can carry.
#[test]
fn argon2id_keys_match_the_reference() {
    for (params, expected) in [
        (
            KdfParams::MIN,
            "d17ea6341ca93da6079ea2f64dc4aa31dd1aaf9caa67fb42ac4afd0714706f26",
        ),
        (WEAK, K_64_1_1),
        (
            KdfParams {
                memory_kib: 64,
                iterations: 2,
                parallelism: 2,
            },
            "de59dad55146fdfff0a3be5022102e01dd6a6dd3fac0fb94576669ed7d71f8d6",
        ),
        (
            KdfParams::DEFAULT,
            "818259b6310026a8e0dbac5d2e6927abcfdb07b32258fac4f61b18b80f929085",
        ),
    ] {
        let key = derive_key(PASSWORD, &salt(), &params).unwrap();
        assert_eq!(*key, hex::<KEY_LEN>(expected), "{params:?}");
    }
}

/// The six parameter bytes of message 2: `m_kib(4, BE) | t | p`.
#[test]
fn kdf_parameters_encode_big_endian() {
    assert_eq!(encode_params(&WEAK), hex::<6>("000000400101"));
    assert_eq!(encode_params(&KdfParams::DEFAULT), hex::<6>("00004c000201"));
}

/// Both proofs are HMAC-SHA256 under `K` over the documented transcript.
#[test]
fn proofs_match_the_reference() {
    let key: [u8; KEY_LEN] = hex(K_64_1_1);
    assert_eq!(
        client_proof(&key, USER, &snonce(), &cnonce(), &salt(), &WEAK),
        hex::<PROOF_LEN>("f46e99e8ff64d0a65ccf4536bace03fd5031770a8b0716b92f2a126754db9ef9"),
    );
    assert_eq!(
        server_proof(&key, USER, &cnonce(), &snonce()),
        hex::<PROOF_LEN>("6ae1d2224366b13d2c78021516d39524ae217c6b1a090d4bb8e0be9468a6b6be"),
    );
}

/// An unknown user's decoy salt and key are `HMAC(decoy_key, label | user)`.
#[test]
fn decoy_answers_match_the_reference() {
    let decoy = DecoyKey::from_bytes([7u8; KEY_LEN]).decoy_secret(USER);
    assert_eq!(
        decoy.salt,
        hex::<16>("e0a2e7a223a35180fd87daf18e290913").to_vec()
    );
    assert_eq!(
        decoy.key(),
        &hex::<KEY_LEN>("4f67250402edb2581d5c1f2a1d001367e6f300c13d1529f1b2f5e3cea1ff91cd"),
    );
}

const A_PRIV: &str = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
const B_PRIV: &str = "2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40";
const A_PUB: &str = "07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c";
const B_PUB: &str = "5869aff450549732cbaaed5e5df9b30a6da31cb0e5742bad5ad4a1a768f1a67b";
const SHARED: &str = "a84dc7c3c8f058b1b2dc4cd1e9b5dc0a7987f88b6a9564cde3391fc421159e77";

/// X25519 public keys and the shared secret for fixed private keys.
#[test]
fn x25519_matches_the_reference() {
    let a: [u8; 32] = hex(A_PRIV);
    let b: [u8; 32] = hex(B_PRIV);
    let a_pub = x25519_dalek::x25519(a, x25519_dalek::X25519_BASEPOINT_BYTES);
    let b_pub = x25519_dalek::x25519(b, x25519_dalek::X25519_BASEPOINT_BYTES);
    assert_eq!(a_pub, hex::<32>(A_PUB));
    assert_eq!(b_pub, hex::<32>(B_PUB));
    assert_eq!(x25519_dalek::x25519(a, b_pub), hex::<32>(SHARED));
    assert_eq!(x25519_dalek::x25519(b, a_pub), hex::<32>(SHARED));
}

const SEALED: &str = "5addea3970216a9d6f3da0b341aec53c5342e637523b9854b63b8282f264ed1ad8dd61df531a40162d9e70232298795fd3e63533d5dbb2368a2bcfb2db4e7828d7cf8ff2e35a0c";

/// The enrollment envelope: HKDF-SHA256 key over the transcript, ChaCha20-
/// Poly1305 with a zero nonce. Sealing is deterministic given the shared
/// secret, so the ciphertext is pinned byte for byte, and the reference's own
/// ciphertext opens.
#[test]
fn the_enrollment_envelope_matches_the_reference() {
    let (cn, sn) = (cnonce(), snonce());
    let (a_pub, b_pub): ([u8; PUBLIC_LEN], [u8; PUBLIC_LEN]) = (hex(A_PUB), hex(B_PUB));
    let transcript = Transcript {
        user: USER,
        cnonce: &cn,
        snonce: &sn,
        client_pub: &a_pub,
        server_pub: &b_pub,
    };
    let shared: [u8; 32] = hex(SHARED);
    let secret = UserSecret::from_parts(salt().to_vec(), WEAK, hex(K_64_1_1)).unwrap();

    assert_eq!(
        seal(&secret, &shared, &transcript).unwrap(),
        hex_vec(SEALED)
    );

    let opened = open(&KdfParams::MIN, &hex_vec(SEALED), &shared, &transcript).unwrap();
    assert_eq!(opened.salt, salt().to_vec());
    assert_eq!(opened.params, WEAK);
    assert_eq!(opened.key(), &hex::<KEY_LEN>(K_64_1_1));
}

struct Fixed(Mutex<HashMap<String, StoredUser>>, DerivationLimiter);

impl SecretStore for Fixed {
    async fn lookup(&self, user: &str) -> Option<StoredUser> {
        self.0.lock().unwrap().get(user).cloned()
    }

    async fn claim(&self, _user: &str, _secret: UserSecret) -> bool {
        false
    }

    fn derivation_limiter(&self) -> &DerivationLimiter {
        &self.1
    }
}

fn mac_of(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
    for part in parts {
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}

/// A hand-written client speaks the documented byte layout to the real
/// server: message 2 is exactly `1 | 0 | slen | salt | m_kib | t | p | snonce`,
/// a proof built from the documented fields is accepted, and message 4 is
/// `1 | 0 | HMAC(K, "resocks5-secure/1 server" | ...)`.
#[tokio::test]
async fn the_server_speaks_the_documented_byte_layout() {
    let key: [u8; KEY_LEN] = hex(K_64_1_1);
    let secret = UserSecret::from_parts(salt().to_vec(), WEAK, key).unwrap();
    let store = Fixed(
        Mutex::new(HashMap::from([(
            "alice".to_owned(),
            StoredUser::Secret(secret),
        )])),
        DerivationLimiter::new(2),
    );
    let decoy = DecoyKey::from_bytes([7u8; KEY_LEN]);
    let (mut client, mut server) = duplex(4096);
    let (served, ()) = tokio::join!(server_authenticate(&mut server, &store, &decoy), async {
        // 1. client -> server: 1 | ulen | user | cnonce
        let mut hello = vec![1, u8::try_from(USER.len()).unwrap()];
        hello.extend_from_slice(USER);
        hello.extend_from_slice(&cnonce());
        client.write_all(&hello).await.unwrap();

        // 2. server -> client
        let mut offer = [0u8; 3 + 16 + 6 + NONCE_LEN];
        client.read_exact(&mut offer).await.unwrap();
        let mut expected_head = vec![1, 0, 16];
        expected_head.extend_from_slice(&salt());
        expected_head.extend_from_slice(&hex::<6>("000000400101"));
        assert_eq!(offer[..3 + 16 + 6], expected_head[..]);
        let snonce: [u8; NONCE_LEN] = offer[3 + 16 + 6..].try_into().unwrap();

        // 3. client -> server: 1 | proof
        let proof = mac_of(
            &key,
            &[
                b"resocks5-secure/1 client",
                &[5],
                USER,
                &snonce,
                &cnonce(),
                &[16],
                &salt(),
                &hex::<6>("000000400101"),
            ],
        );
        let mut reply = vec![1];
        reply.extend_from_slice(&proof);
        client.write_all(&reply).await.unwrap();

        // 4. server -> client: 1 | 0 | server_proof
        let mut done = [0u8; 2 + PROOF_LEN];
        client.read_exact(&mut done).await.unwrap();
        assert_eq!(done[..2], [1, 0]);
        let expected = mac_of(
            &key,
            &[b"resocks5-secure/1 server", &[5], USER, &cnonce(), &snonce],
        );
        assert_eq!(done[2..], expected);
    });
    assert_eq!(served.unwrap(), "alice");
}
