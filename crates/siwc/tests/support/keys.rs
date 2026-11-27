//! Synthetic signing keys for the fake provider. Generated for this test
//! suite; they protect nothing.

use ring::rand::SystemRandom;
use ring::signature::{RSA_PKCS1_SHA256, RsaKeyPair, RsaPublicKeyComponents};
use ring::{hmac, signature::KeyPair};
use serde_json::{Value, json};

use super::wire::base64url;

pub struct SigningKey {
    pair: RsaKeyPair,
    pub id: &'static str,
}

impl SigningKey {
    /// The key the fake provider publishes and signs with.
    pub fn provider() -> Self {
        Self::load(include_bytes!("keys/provider.der"), "provider-key-1")
    }

    /// A key the provider does not publish.
    pub fn other() -> Self {
        Self::load(include_bytes!("keys/other.der"), "other-key-1")
    }

    fn load(der: &[u8], id: &'static str) -> Self {
        Self {
            pair: RsaKeyPair::from_der(der).expect("test key"),
            id,
        }
    }

    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let mut signature = vec![0; self.pair.public().modulus_len()];
        self.pair
            .sign(
                &RSA_PKCS1_SHA256,
                &SystemRandom::new(),
                message,
                &mut signature,
            )
            .expect("rsa signature");
        signature
    }

    /// An HS256 tag keyed with the public key: what an attacker who only
    /// knows the published key can produce.
    pub fn hmac_with_public_key(&self, message: &[u8]) -> Vec<u8> {
        let key = hmac::Key::new(hmac::HMAC_SHA256, self.pair.public_key().as_ref());
        hmac::sign(&key, message).as_ref().to_vec()
    }

    pub fn jwk(&self) -> Value {
        let public = RsaPublicKeyComponents::<Vec<u8>>::from(self.pair.public());
        json!({
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": self.id,
            "n": base64url(&public.n),
            "e": base64url(&public.e),
        })
    }
}

/// A compact JWS over `header` and `claims`, signed by `sign`.
pub fn jwt(header: &Value, claims: &Value, sign: impl FnOnce(&[u8]) -> Vec<u8>) -> String {
    let signed = format!(
        "{}.{}",
        base64url(header.to_string().as_bytes()),
        base64url(claims.to_string().as_bytes())
    );
    let signature = sign(signed.as_bytes());
    format!("{signed}.{}", base64url(&signature))
}
