//! A software passkey, enough to run the sign-in pages' ceremonies as a
//! browser and a platform authenticator would: a P-256 key, "none"
//! attestation, and the user verified.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use openssl::bn::BigNumContext;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::sha::sha256;
use openssl::sign::Signer;
use serde_json::{Value, json};

/// User present, user verified, and for a new credential, its data attached.
const PRESENT_AND_VERIFIED: u8 = 0x01 | 0x04;
const ATTESTED: u8 = 0x40;

pub struct SoftPasskey {
    key: EcKey<Private>,
    pub id: Vec<u8>,
    /// The account's id as the server named it, which a discoverable
    /// credential hands back.
    pub user: Vec<u8>,
    counter: u32,
}

fn bytes(value: &Value) -> Vec<u8> {
    URL_SAFE_NO_PAD
        .decode(value.as_str().expect("a base64url string"))
        .unwrap()
}

fn text(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn client_data(kind: &str, options: &Value, origin: &str) -> Vec<u8> {
    json!({
        "type": kind,
        "challenge": options["publicKey"]["challenge"],
        "origin": origin,
        "crossOrigin": false,
    })
    .to_string()
    .into_bytes()
}

impl SoftPasskey {
    /// Answers `navigator.credentials.create` with the server's options.
    pub fn create(options: &Value, origin: &str) -> (Self, Value) {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let key = EcKey::generate(&group).unwrap();
        let passkey = Self {
            id: ilo_server::db::random_bytes::<16>().to_vec(),
            user: bytes(&options["publicKey"]["user"]["id"]),
            key,
            counter: 0,
        };
        let rp = options["publicKey"]["rp"]["id"].as_str().unwrap();
        let mut auth_data = passkey.auth_data(rp, PRESENT_AND_VERIFIED | ATTESTED);
        auth_data.extend([0; 16]);
        auth_data.extend((passkey.id.len() as u16).to_be_bytes());
        auth_data.extend(&passkey.id);
        auth_data.extend(passkey.cose_key());
        // {"fmt": "none", "attStmt": {}, "authData": auth_data}, in CBOR.
        let mut attestation = vec![0xa3, 0x63];
        attestation.extend(b"fmt");
        attestation.push(0x64);
        attestation.extend(b"none");
        attestation.push(0x67);
        attestation.extend(b"attStmt");
        attestation.extend([0xa0, 0x68]);
        attestation.extend(b"authData");
        attestation.extend([0x58, auth_data.len() as u8]);
        attestation.extend(&auth_data);
        let credential = json!({
            "id": text(&passkey.id),
            "rawId": text(&passkey.id),
            "type": "public-key",
            "response": {
                "attestationObject": text(&attestation),
                "clientDataJSON": text(&client_data("webauthn.create", options, origin)),
            },
            "extensions": {},
        });
        (passkey, credential)
    }

    /// Answers `navigator.credentials.get`, as a discoverable credential
    /// does: with the user's id, whatever credentials the options name.
    pub fn get(&mut self, options: &Value, origin: &str) -> Value {
        self.counter += 1;
        let rp = options["publicKey"]["rpId"].as_str().unwrap();
        let auth_data = self.auth_data(rp, PRESENT_AND_VERIFIED);
        let client_data = client_data("webauthn.get", options, origin);
        let mut signed = auth_data.clone();
        signed.extend(sha256(&client_data));
        let key = PKey::from_ec_key(self.key.clone()).unwrap();
        let mut signer = Signer::new(MessageDigest::sha256(), &key).unwrap();
        signer.update(&signed).unwrap();
        json!({
            "id": text(&self.id),
            "rawId": text(&self.id),
            "type": "public-key",
            "response": {
                "authenticatorData": text(&auth_data),
                "clientDataJSON": text(&client_data),
                "signature": text(&signer.sign_to_vec().unwrap()),
                "userHandle": text(&self.user),
            },
            "extensions": {},
        })
    }

    fn auth_data(&self, rp: &str, flags: u8) -> Vec<u8> {
        let mut data = sha256(rp.as_bytes()).to_vec();
        data.push(flags);
        data.extend(self.counter.to_be_bytes());
        data
    }

    /// The public key as COSE: {kty: EC2, alg: ES256, crv: P-256, x, y}.
    fn cose_key(&self) -> Vec<u8> {
        let mut x = openssl::bn::BigNum::new().unwrap();
        let mut y = openssl::bn::BigNum::new().unwrap();
        self.key
            .public_key()
            .affine_coordinates(
                self.key.group(),
                &mut x,
                &mut y,
                &mut BigNumContext::new().unwrap(),
            )
            .unwrap();
        let mut key = vec![0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20];
        key.extend(x.to_vec_padded(32).unwrap());
        key.extend([0x22, 0x58, 0x20]);
        key.extend(y.to_vec_padded(32).unwrap());
        key
    }
}
