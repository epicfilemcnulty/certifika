//! module to work with JSON Web Signatures -- [RFC7515](https://tools.ietf.org/html/rfc7515).
//! The module supports signing with ECDSA P-256 keys only.

use anyhow::Result;
use ring::rand;
use ring::signature::EcdsaKeyPair;
use ring::signature::KeyPair;
use std::collections::HashMap;

/// a shortcut function to use base64 URL-safe encoding with no padding.
///
/// **RFC8555** says that *...binary fields in the JSON objects
/// used by ACME are encoded using base64url encoding described in
/// Section 5 of [RFC4648] according to the profile specified in
/// JSON Web Signature in Section 2 of [RFC7515]. This encoding uses a URL safe
/// character set. Trailing '=' characters MUST be stripped. Encoded values that include
/// trailing '=' characters MUST be rejected as improperly encoded*
pub fn b64(data: &[u8]) -> String {
    base64::encode_config(data, base64::URL_SAFE_NO_PAD)
}

/// Generates JWK from a public key of EcdsaKeyPair. See [RFC7517](https://tools.ietf.org/html/rfc7517) on JWK,
/// and [RFC7518](https://tools.ietf.org/html/rfc7518) on JWA and different JWK parameters.
pub fn jwk(public_key: &[u8]) -> Result<serde_json::Value> {
    // First octect of the public key says whether it's uncompressed (04) or not (03 o 02).
    // After that it has X and Y coordinates, each 32 bytes long. We know that we are dealing
    // with the uncompressed key of the same length all the time, so we can do this:
    let x_comp: Vec<u8> = public_key.iter().skip(1).take(32).copied().collect();
    let y_comp: Vec<u8> = public_key.iter().skip(33).take(32).copied().collect();
    let mut jwk: HashMap<String, String> = HashMap::new();
    jwk.insert("crv".to_owned(), "P-256".to_owned());
    jwk.insert("kty".to_owned(), "EC".to_owned());
    jwk.insert("x".to_owned(), b64(x_comp.as_slice()));
    jwk.insert("y".to_owned(), b64(y_comp.as_slice()));
    Ok(serde_json::to_value(jwk)?)
}

/// Signs the `payload` and returns the signature as a string.
pub fn sign(
    key_pair: &EcdsaKeyPair,
    nonce: &str,
    url: &str,
    payload: String,
    kid: Option<&str>,
) -> Result<String> {
    let mut data: HashMap<String, serde_json::Value> = HashMap::new();

    // payload
    let payload64 = b64(&payload.into_bytes());
    data.insert("payload".to_owned(), serde_json::to_value(&payload64)?);

    // protected header
    let mut header: HashMap<String, serde_json::Value> = HashMap::new();
    header.insert("alg".to_owned(), serde_json::to_value("ES256")?);
    match kid {
        None => header.insert("jwk".to_owned(), jwk(key_pair.public_key().as_ref())?),
        Some(k) => header.insert("kid".to_owned(), serde_json::to_value(k)?),
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
