//! Signs ID tokens with ES256. The key is made on first start and kept in the
//! database, so a server needs no secret in its environment.

use anyhow::Context;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroup, EcKey};
use openssl::ecdsa::EcdsaSig;
use openssl::nid::Nid;
use openssl::pkey::Private;
use serde_json::{Value, json};

use crate::db::{self, Db};

pub struct Signer {
    id: String,
    key: EcKey<Private>,
}

impl Signer {
    pub async fn load_or_create(db: &Db) -> anyhow::Result<Self> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let fresh = EcKey::generate(&group)?;
        let pem = String::from_utf8(fresh.private_key_to_pem()?)?;
        // Two instances starting at once agree on the oldest key.
        sqlx::query(
            "INSERT INTO signing_keys (id, private_key, created_at) VALUES ($1, $2, $3) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(db::random_id())
        .bind(pem)
        .bind(db::now())
        .execute(db)
        .await?;
        let (id, pem): (String, String) = sqlx::query_as(
            "SELECT id, private_key FROM signing_keys ORDER BY created_at, id LIMIT 1",
        )
        .fetch_one(db)
        .await?;
        let key =
            EcKey::private_key_from_pem(pem.as_bytes()).context("a signing key is corrupt")?;
        Ok(Self { id, key })
    }

    pub fn sign(&self, claims: &Value) -> anyhow::Result<String> {
        let header = json!({"alg": "ES256", "typ": "JWT", "kid": self.id});
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims)?)
        );
        let signature = EcdsaSig::sign(&openssl::sha::sha256(input.as_bytes()), &self.key)?;
        // JWS wants r and s side by side, not DER.
        let mut raw = signature.r().to_vec_padded(32)?;
        raw.extend(signature.s().to_vec_padded(32)?);
        Ok(format!("{input}.{}", URL_SAFE_NO_PAD.encode(raw)))
    }

    pub fn jwks(&self) -> anyhow::Result<Value> {
        let group = self.key.group();
        let (mut x, mut y) = (BigNum::new()?, BigNum::new()?);
        let mut context = BigNumContext::new()?;
        self.key
            .public_key()
            .affine_coordinates(group, &mut x, &mut y, &mut context)?;
        Ok(json!({"keys": [{
            "kty": "EC",
            "crv": "P-256",
            "use": "sig",
            "alg": "ES256",
            "kid": self.id,
            "x": URL_SAFE_NO_PAD.encode(x.to_vec_padded(32)?),
            "y": URL_SAFE_NO_PAD.encode(y.to_vec_padded(32)?),
        }]}))
    }
}
