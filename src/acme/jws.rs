//! module to work with JSON Web Signatures -- [RFC7515](https://tools.ietf.org/html/rfc7515).
//! There is a single public function, `jws::sign()`, and the module supports
//! signing with ECDSA P-256 keys only.

use ring::rand;
use ring::signature::EcdsaKeyPair;
use ring::signature::KeyPair;
use serde::Serialize;
use std::collections::HashMap;
use std::error::Error;

// RFC8555:
// Binary fields in the JSON objects used by ACME are encoded using
// base64url encoding described in Section 5 of [RFC4648] according to
// the profile specified in JSON Web Signature in Section 2 of
// [RFC7515]. This encoding uses a URL safe character set. Trailing
// '=' characters MUST be stripped. Encoded values that include
// trailing '=' characters MUST be rejected as improperly encoded.
fn b64(data: &[u8]) -> String {
    base64::encode_config(data, base64::URL_SAFE_NO_PAD)
}

fn jwk(key_pair: &EcdsaKeyPair) -> Result<serde_json::Value, Box<dyn Error>> {
    // See https://tools.ietf.org/html/rfc7518#section-6.1 for more info
    // on JWK key parameters
    let public_key = key_pair.public_key().as_ref();
    // First octect of the public key says whether it's uncompressed (04) or not (03 o 02).
    // After that it has X and Y coordinates, each 32 bytes long.
    let x_comp: Vec<u8> = public_key
        .iter()
        .skip(1)
        .take(32)
        .map(|&x| x)
        .to_owned()
        .collect();
    let y_comp: Vec<u8> = public_key
        .iter()
        .skip(33)
        .take(32)
        .map(|&x| x)
        .to_owned()
        .collect();
    let mut jwk: HashMap<String, String> = HashMap::new();
    jwk.insert("kty".to_owned(), "EC".to_owned());
    jwk.insert("crv".to_owned(), "P-256".to_owned());
    jwk.insert("x".to_owned(), b64(x_comp.as_slice()));
    jwk.insert("y".to_owned(), b64(y_comp.as_slice()));
    Ok(serde_json::to_value(jwk)?)
}

pub fn sign<T: Serialize>(
    key_pair: &EcdsaKeyPair,
    nonce: &str,
    url: &str,
    payload: T,
    kid: &str,
) -> Result<String, Box<dyn Error>> {
    let mut data: HashMap<String, serde_json::Value> = HashMap::new();

    // payload: b64 of payload
    let payload = serde_json::to_string(&payload)?;
    let payload64 = b64(&payload.into_bytes());
    data.insert("payload".to_owned(), serde_json::to_value(&payload64)?);

    // protected header
    let mut header: HashMap<String, serde_json::Value> = HashMap::new();
    header.insert("alg".to_owned(), serde_json::to_value("ES256")?);
    if kid == "" {
        header.insert("jwk".to_owned(), jwk(key_pair)?);
    } else {
        header.insert("kid".to_owned(), serde_json::to_value(kid)?);
    };
    header.insert("nonce".to_owned(), serde_json::to_value(nonce)?);
    header.insert("url".to_owned(), serde_json::to_value(url)?);
    let protected = b64(&serde_json::to_string(&header)?.into_bytes());
    data.insert("protected".to_owned(), serde_json::to_value(&protected)?);

    // signature
    let rng = rand::SystemRandom::new();
    data.insert(
        "signature".to_owned(),
        serde_json::to_value(b64(&key_pair
            .sign(&rng, &format!("{}.{}", protected, payload64).into_bytes())
            .unwrap()
            .as_ref()))?,
    );
    Ok(serde_json::to_string(&data)?)
}
