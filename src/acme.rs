use reqwest::blocking::Client;
use reqwest::header::USER_AGENT;
use reqwest::StatusCode;
use ring::{
    rand,
    signature::{self, EcdsaKeyPair},
};
use serde::Serialize;
use std::collections::HashMap;
use std::error::Error;

pub const USER_AGENT_VALUE: &'static str = "certifika 0.1/reqwest 0.10";
pub const LETSENCRYPT_DIRECTORY_URL: &'static str =
    "https://acme-staging-v02.api.letsencrypt.org/directory";

#[derive(Debug)]
pub struct Directory {
    url: String,
    directory: serde_json::Value,
}

impl Directory {
    pub fn lets_encrypt() -> Result<Directory, Box<dyn Error>> {
        Directory::from_url(LETSENCRYPT_DIRECTORY_URL)
    }

    pub fn from_url(url: &str) -> Result<Directory, Box<dyn Error>> {
        let client = Client::new();
        let res = client
            .get(url)
            .header(USER_AGENT, USER_AGENT_VALUE)
            .send()?;
        let content = res.text()?; // probably better just use "directory: res.json()?," in the Ok variant
        Ok(Directory {
            url: url.to_owned(),
            directory: serde_json::from_str(&content)?,
        })
    }

    pub fn register_account(self, email: &str) -> Result<Account, Box<dyn Error>> {
        let acc = Account {
            directory: self,
            key_pair: Account::generate_keypair().unwrap(),
        };
        let mut payload = HashMap::new();
        let mut contact: Vec<String> = Vec::new();
        contact.push(format!("mailto:{}", email.to_owned())); // <--- probably gotta convert this to string
        payload.insert(
            "termsOfServiceAgreed".to_owned(),
            serde_json::to_value(true)?,
        );
        payload.insert("contact".to_owned(), serde_json::to_value(contact)?);
        let (status_code, response) =
            acc.directory
                .request(&acc.key_pair, "newAccount", payload)?;
        if status_code.is_success() {
            println!("{:?}", response);
            Ok(acc)
        } else {
            Err(format!("failed to register account - {}", response).into())
        }
    }

    /// Returns url for the resource.
    fn url_for(&self, resource: &str) -> Option<&str> {
        self.directory
            .as_object()
            .and_then(|o| o.get(resource))
            .and_then(|k| k.as_str())
    }

    fn get_nonce(&self) -> Result<String, Box<dyn Error>> {
        let url = self.url_for("newNonce").unwrap();
        let client = Client::new();
        let res = client.head(url).send()?;
        let nonce = res.headers().get("Replay-Nonce").unwrap();
        Ok(nonce.to_str().unwrap().to_string())
    }

    fn request<T: Serialize>(
        &self,
        key_pair: &EcdsaKeyPair,
        resource: &str,
        payload: T,
    ) -> Result<(StatusCode, serde_json::Value), Box<dyn Error>> {
        let json = serde_json::to_value(&payload)?;
        let url = self.url_for(resource).unwrap();
        // let url = "http://127.0.0.1:88";
        let nonce = self.get_nonce()?;
        let jws = jws::sign(&key_pair, &nonce, url, json)?;
        let client = Client::new();
        println!("{:#?}", jws);
        let req = client
            .post(url)
            .header(USER_AGENT, USER_AGENT_VALUE)
            .header("content-type", "application/jose+json")
            .body(jws);
        println!("{:#?}", req);
        let res = req.send()?;
        println!("{:#?}", res);
        Ok((res.status(), res.json()?))
    }
}

#[derive(Debug)]
pub struct Account {
    directory: Directory,
    key_pair: EcdsaKeyPair,
}

impl Account {
    pub fn generate_keypair() -> Result<EcdsaKeyPair, Box<dyn Error>> {
        // Generate a key pair in PKCS#8 (v2) format.
        let rng = rand::SystemRandom::new();
        let alg = &signature::ECDSA_P256_SHA256_ASN1_SIGNING;
        let pkcs8 = signature::EcdsaKeyPair::generate_pkcs8(alg, &rng).unwrap();
        let key_pair = signature::EcdsaKeyPair::from_pkcs8(alg, pkcs8.as_ref()).unwrap();
        Ok(key_pair)
    }
}

mod jws {

    use ring::rand;
    use ring::signature::EcdsaKeyPair;
    use ring::signature::KeyPair;
    use std::collections::HashMap;
    use std::error::Error;
    extern crate base64;
    use serde::Serialize;

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
    ) -> Result<String, Box<dyn Error>> {
        let mut data: HashMap<String, serde_json::Value> = HashMap::new();

        // payload: b64 of payload
        let payload = serde_json::to_string(&payload)?;
        let payload64 = b64(&payload.into_bytes());
        data.insert("payload".to_owned(), serde_json::to_value(&payload64)?);

        // protected header
        let mut header: HashMap<String, serde_json::Value> = HashMap::new();
        header.insert("alg".to_owned(), serde_json::to_value("ES256")?);
        header.insert("jwk".to_owned(), jwk(key_pair)?);
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
}
