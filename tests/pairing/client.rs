//! The client's side of pairing, as `docs/protocol.md` specifies it: what
//! ilo's devices do around the server's frames. OpenSSL here; the engine has
//! the same primitives in BoringSSL.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use openssl::derive::Deriver;
use openssl::md::Md;
use openssl::pkey::{Id, PKey, Private};
use openssl::pkey_ctx::PkeyCtx;
use openssl::sha::Sha256;
use openssl::symm::{Cipher, decrypt_aead, encrypt_aead};

pub type Key = [u8; 32];

/// A key pair made for one pairing, and dropped after it.
pub struct KeyPair {
    private: PKey<Private>,
    pub public: Key,
}

impl KeyPair {
    pub fn generate() -> KeyPair {
        let private = PKey::generate_x25519().unwrap();
        let public = private.raw_public_key().unwrap().try_into().unwrap();
        KeyPair { private, public }
    }

    pub fn from_private(private: &Key) -> KeyPair {
        let private = PKey::private_key_from_raw_bytes(private, Id::X25519).unwrap();
        let public = private.raw_public_key().unwrap().try_into().unwrap();
        KeyPair { private, public }
    }
}

pub fn text(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn bytes(text: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(text).ok()
}

pub fn key(text: &str) -> Option<Key> {
    bytes(text)?.try_into().ok()
}

fn hash(label: &str, parts: &[&[u8]]) -> Key {
    let mut hasher = Sha256::new();
    hasher.update(label.as_bytes());
    for part in parts {
        hasher.update(part);
    }
    hasher.finish()
}

/// What the new device sends first in place of its key, so that no one in
/// the middle can pick a key to match the code after seeing the other's.
pub fn commitment(requester: &Key) -> Key {
    hash("ilo pairing v1 commitment", &[requester])
}

/// The six digits both screens show.
pub fn match_code(requester: &Key, approver: &Key) -> String {
    let digest = hash("ilo pairing v1 code", &[requester, approver]);
    let number = u64::from_be_bytes(digest[..8].try_into().unwrap()) % 1_000_000;
    format!("{number:06}")
}

/// X25519 between this pairing's two keys, through HKDF-SHA256, bound to both.
fn seal_key(own: &KeyPair, other: &Key, requester: &Key, approver: &Key) -> Option<Key> {
    let peer = PKey::public_key_from_raw_bytes(other, Id::X25519).ok()?;
    let mut deriver = Deriver::new(&own.private).ok()?;
    deriver.set_peer(&peer).ok()?;
    let shared = deriver.derive_to_vec().ok()?;
    // A low-order key gives all zeros, which anyone could compute.
    if shared.iter().all(|&byte| byte == 0) {
        return None;
    }
    let mut hkdf = PkeyCtx::new_id(Id::HKDF).unwrap();
    hkdf.derive_init().unwrap();
    hkdf.set_hkdf_md(Md::sha256()).unwrap();
    hkdf.set_hkdf_key(&shared).unwrap();
    hkdf.set_hkdf_salt(&hash("ilo pairing v1 keys", &[requester, approver]))
        .unwrap();
    hkdf.add_hkdf_info(b"ilo pairing v1 seal").unwrap();
    let mut key = [0; 32];
    hkdf.derive(Some(&mut key)).unwrap();
    Some(key)
}

/// The approver seals the account's secret to the new device. The key is
/// used once, so the nonce is zeros; the pairing's id is the associated data.
pub fn seal(approver: &KeyPair, requester: &Key, pairing: &str, secret: &Key) -> Option<Vec<u8>> {
    let key = seal_key(approver, requester, requester, &approver.public)?;
    let mut tag = [0; 16];
    let mut sealed = encrypt_aead(
        Cipher::chacha20_poly1305(),
        &key,
        Some(&[0; 12]),
        pairing.as_bytes(),
        secret,
        &mut tag,
    )
    .ok()?;
    sealed.extend_from_slice(&tag);
    Some(sealed)
}

pub fn open(requester: &KeyPair, approver: &Key, pairing: &str, sealed: &[u8]) -> Option<Key> {
    let key = seal_key(requester, approver, &requester.public, approver)?;
    let (ciphertext, tag) = sealed.split_at_checked(sealed.len().checked_sub(16)?)?;
    let secret = decrypt_aead(
        Cipher::chacha20_poly1305(),
        &key,
        Some(&[0; 12]),
        pairing.as_bytes(),
        ciphertext,
        tag,
    )
    .ok()?;
    secret.try_into().ok()
}
