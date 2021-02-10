//! module to work with Let's Encrypt API, i.e. ACME protocol ([RFC8555](https://tools.ietf.org/html/rfc8555))
//!
//! Provides all basics objects and methods to register a new ACME account, order
//! and fetch certificates.
//!
//! # Examples
//!
//! ## Register a new account
//! ```
//! let store = storage::FileStore::init(&"/tmp/certifika").unwrap()
//! let account = acme::Account::new("some@email.com".as_str(), &store).unwrap();
//! ```
use crate::storage::{ObjectKind, Store};
use crate::{APP_NAME, APP_VERSION};
use anyhow::anyhow;
use ring::{
    digest, rand,
    signature::{self, EcdsaKeyPair, KeyPair},
};
use serde::{Deserialize, Serialize};
use std::{thread, time};
use thiserror::Error;
mod jws;

pub const HTTP_CLIENT_LIB: &str = "ureq 2.0.1";
pub const LETSENCRYPT_DIRECTORY_URL: &str =
    "https://acme-staging-v02.api.letsencrypt.org/directory";

#[derive(Error, Debug)]
pub enum AcmeError {
    #[error("ACME API: {0:?}")]
    Api(ureq::Error),
    #[error("JSON encode: {0:?}")]
    JsonEncode(std::io::Error),
    #[error("JSON decode: {0:?}")]
    JsonDecode(serde_json::error::Error),
    #[error("Storage: {0:?}")]
    Store(crate::storage::StoreError),
    #[error("ECDSA key decode: {0:?}")]
    KeyDecode(ring::error::KeyRejected),
    #[error("ECDSA key generation: {0:?}")]
    KeyGen(ring::error::Unspecified),
    #[error("UTF8 processing: {0:?}")]
    Utf8(std::str::Utf8Error),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// Let's Encrypt [directory](https://tools.ietf.org/html/rfc8555#section-7.1.1) object struct. Usually you don't need
/// to interact with it directly, the `Account` struct includes
/// this struct and does all interactions with it behind the scenes.
#[derive(Debug, Serialize, Deserialize)]
struct Directory {
    url: String,
    directory: serde_json::Value,
}

impl Directory {
    /// a wrapper around `Self::from_url()` method to create
    /// a new instance from the default Let's Encrypt URL.
    pub fn lets_encrypt() -> Result<Directory, AcmeError> {
        Directory::from_url(LETSENCRYPT_DIRECTORY_URL)
    }
    /// method to create a new Directory instance from an URL.
    pub fn from_url(url: &str) -> Result<Directory, AcmeError> {
        let agent = ureq::AgentBuilder::new().build();
        let response = agent
            .get(url)
            .set("User-Agent", &http_user_agent())
            .call()
            .map_err(AcmeError::Api)?;
        Ok(Directory {
            url: url.to_owned(),
            directory: response.into_json().map_err(AcmeError::JsonEncode)?,
        })
    }

    /// `self.directory` field has a JSON directory object we got from Let's Encrypt. It has links to all Let's Encrypt resources:
    /// ```json
    ///   {
    ///     "newAccount": "https://acme.example.com/acme/new-account",
    ///     "newOrder": "https://acme.example.com/acme/new-order"
    ///   }
    ///  ```
    /// `url_for` maps resource name to the link and returns it.
    fn url_for(&self, resource: &str) -> Option<&str> {
        self.directory
            .as_object()
            .and_then(|o| o.get(resource))
            .and_then(|k| k.as_str())
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Identifier {
    #[serde(rename = "type")]
    _type: String,
    value: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Order {
    status: String,
    expires: String,
    identifiers: Vec<Identifier>,
    authorizations: Vec<String>,
    finalize: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Challenge {
    #[serde(rename = "type")]
    _type: String,
    status: String,
    url: String,
    token: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Authorization {
    identifier: Identifier,
    status: String,
    expires: String,
    challenges: Vec<Challenge>,
}

/// struct for the ACME [Account](https://tools.ietf.org/html/rfc8555#section-7.1.2) object.
pub struct Account<'a> {
    store: &'a dyn Store,
    email: String,
    directory: Directory,
    key_pair: EcdsaKeyPair,
    pkcs8: Vec<u8>,
    nonce: Option<String>,
    kid: Option<String>,
}

impl<'a> Account<'a> {
    /// Tries to register a new ACME account.
    pub fn new(email: String, store: &'a dyn Store) -> Result<Account<'a>, AcmeError> {
        let (key_pair, pkcs8) = Account::generate_keypair()?;
        let mut acc = Account {
            email,
            store,
            directory: Directory::lets_encrypt()?,
            key_pair,
            pkcs8,
            nonce: None,
            kid: None,
        };
        acc.nonce = Some(acc.get_nonce()?);
        acc.register()?;
        acc.save()?;
        Ok(acc)
    }

    pub fn save(&self) -> Result<(), AcmeError> {
        self.store
            .write(ObjectKind::KeyPair, &self.email, self.pkcs8.as_ref())
            .map_err(AcmeError::Store)?;
        self.store
            .write(
                ObjectKind::Account,
                &self.email,
                self.kid.to_owned().unwrap().as_bytes(),
            )
            .map_err(AcmeError::Store)?;
        let payload = serde_json::to_string(&self.directory).map_err(AcmeError::JsonDecode)?;
        self.store
            .write(ObjectKind::Directory, &self.email, payload.as_bytes())
            .map_err(AcmeError::Store)?;
        Ok(())
    }

    pub fn load(email: String, store: &'a dyn Store) -> Result<Account<'a>, AcmeError> {
        let alg = &signature::ECDSA_P256_SHA256_FIXED_SIGNING;
        let pkcs8 = store
            .read(ObjectKind::KeyPair, &email)
            .map_err(AcmeError::Store)?;
        let key_pair = signature::EcdsaKeyPair::from_pkcs8(alg, pkcs8.as_ref())
            .map_err(AcmeError::KeyDecode)?;
        let dir = serde_json::from_slice(
            &store
                .read(ObjectKind::Directory, &email)
                .map_err(AcmeError::Store)?,
        )
        .map_err(AcmeError::JsonDecode)?;
        let mut acc = Account {
            email,
            directory: dir,
            store,
            key_pair,
            pkcs8,
            nonce: None,
            kid: None,
        };
        acc.nonce = Some(acc.get_nonce()?);
        acc.kid = Some(
            std::str::from_utf8(
                &acc.store
                    .read(ObjectKind::Account, &acc.email)
                    .map_err(AcmeError::Store)?,
            )
            .map_err(AcmeError::Utf8)?
            .to_string(),
        );
        Ok(acc)
    }

    pub fn order(&mut self, domains: Vec<String>) -> Result<(), AcmeError> {
        #[derive(Debug, Serialize, Deserialize)]
        struct OrderReq {
            identifiers: Vec<Identifier>,
        }
        let mut ids: Vec<Identifier> = Vec::new();
        for domain in domains {
            ids.push(Identifier {
                _type: "dns".to_string(),
                value: domain,
            });
        }
        let payload =
            serde_json::to_string(&OrderReq { identifiers: ids }).map_err(AcmeError::JsonDecode)?;
        let (status_code, response) = self.request("newOrder", payload)?;
        if http_status_ok(status_code) {
            let order: Order = serde_json::from_str(&response).map_err(AcmeError::JsonDecode)?;
            for auth in &order.authorizations {
                let a = self.authorization(&auth)?;
                for c in &a.challenges {
                    if c._type == "dns-01" {
                        let ka = self.key_authorization(&c.token);
                        self.trigger_challenge(&c.url);
                        let two_seconds = time::Duration::new(2, 0);
                        thread::sleep(two_seconds);
                        self.challenge_status(&c.url);
                    }
                }
            }
            Ok(())
        } else {
            Err(AcmeError::Other(anyhow!("order failed: {:?}", response)))
        }
    }

    fn authorization(&mut self, url: &str) -> Result<Authorization, AcmeError> {
        let (status_code, response) = self.request(url, "".to_string())?;
        if http_status_ok(status_code) {
            Ok(serde_json::from_str(&response).map_err(AcmeError::JsonDecode)?)
        } else {
            Err(AcmeError::Other(anyhow!(
                "authorization failed: {:?}",
                response
            )))
        }
    }

    fn trigger_challenge(&mut self, url: &str) {
        let (status_code, response) = self.request(url, "{}".to_string()).unwrap();
        log::info!(
            r#"{{"op":"challenge start","status":{},"response":{}}}"#,
            status_code,
            response
        );
    }

    fn challenge_status(&mut self, url: &str) {
        let (status_code, response) = self.request(url, "".to_string()).unwrap();
        log::info!(
            r#"{{"op":"challenge status","status":{},"response":{}}}"#,
            status_code,
            response
        );
    }

    pub fn info(&mut self) {
        let url = self.kid.as_ref().unwrap().to_owned();
        let (status_code, response) = self.request(&url, "".to_string()).unwrap();
        log::info!(
            r#"{{"op":"account info","status":{},"response":{}}}"#,
            status_code,
            response
        );
    }

    /// Generates an ECDSA (P-265 curve) keypair.
    fn generate_keypair() -> Result<(EcdsaKeyPair, Vec<u8>), AcmeError> {
        // Generate a key pair in PKCS#8 (v2) format.
        let rng = rand::SystemRandom::new();
        let alg = &signature::ECDSA_P256_SHA256_FIXED_SIGNING;
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(alg, &rng).map_err(AcmeError::KeyGen)?;
        let key_pair =
            EcdsaKeyPair::from_pkcs8(alg, pkcs8.as_ref()).map_err(AcmeError::KeyDecode)?;
        Ok((key_pair, pkcs8.as_ref().to_owned()))
    }

    fn register(&mut self) -> Result<(), AcmeError> {
        #[derive(Debug, Serialize, Deserialize)]
        struct Registration {
            contact: Vec<String>,
            #[serde(rename = "termsOfServiceAgreed")]
            terms_of_service_agreed: bool,
        }
        let payload = serde_json::to_string(&Registration {
            contact: vec![format!("mailto:{}", self.email.to_owned())],
            terms_of_service_agreed: true,
        })
        .map_err(AcmeError::JsonDecode)?;
        let (status_code, response) = self.request("newAccount", payload)?;
        if http_status_ok(status_code) {
            Ok(())
        } else {
            Err(AcmeError::Other(anyhow!(
                "registration failed: {:?}",
                response
            )))
        }
    }

    /// Function to calculate [Key Authorization](https://tools.ietf.org/html/rfc8555#section-8.1). Basically, it's a token from the challenge + base64url encoded SHA256 hash
    /// of the jwk.
    pub fn key_authorization(&self, token: &str) -> String {
        let jwk = jws::jwk(self.key_pair.public_key().as_ref())
            .unwrap()
            .to_string();
        let hash = digest::digest(&digest::SHA256, jwk.as_bytes());
        let key_authorization = format!("{}.{}", token, jws::b64(hash.as_ref()));
        key_authorization
    }

    fn get_nonce(&self) -> Result<String, AcmeError> {
        let url = self.directory.url_for("newNonce").unwrap();
        let agent = ureq::AgentBuilder::new().build();
        let response = agent
            .head(url)
            .set("User-Agent", &http_user_agent())
            .call()
            .map_err(AcmeError::Api)?;
        let nonce = response.header("Replay-Nonce").unwrap();
        Ok(nonce.to_string())
    }

    fn request(&mut self, resource: &str, payload: String) -> Result<(u16, String), AcmeError> {
        let url = match self.directory.url_for(resource) {
            None => resource,
            Some(u) => u,
        };
        let nonce = self.nonce.as_ref().unwrap();
        let body = if !payload.is_empty() {
            payload.clone()
        } else {
            "\"\"".to_string()
        };
        log::debug!(r#"{{"op":"request","url":"{}","body":{}}}"#, url, body);
        let jws = jws::sign(&self.key_pair, &nonce, &url, payload, self.kid.as_deref())
            .map_err(AcmeError::Other)?;
        let agent = ureq::AgentBuilder::new().build();
        let response = agent
            .post(url)
            .set("User-Agent", &http_user_agent())
            .set("Content-Type", "application/jose+json")
            .send_string(&jws)
            .map_err(AcmeError::Api)?;
        let nonce = response.header("Replay-Nonce").unwrap();
        self.nonce = Some(nonce.to_string());
        log::debug!(
            r#"{{"op":"request responded","status":{}}}"#,
            response.status()
        );
        if http_status_ok(response.status()) {
            if resource == "newAccount" {
                let kid = response.header("Location").unwrap_or("none");
                self.kid = Some(kid.to_string());
            }
            Ok((
                response.status(),
                response.into_string().map_err(AcmeError::JsonEncode)?,
            ))
        } else {
            Err(AcmeError::Other(anyhow!("request failed: {:?}", response)))
        }
    }
}

fn http_status_ok(status: u16) -> bool {
    (200..300).contains(&status)
}

/// **RFC8555** says that all ACME clients should send user-agent header,
/// consisting of the client's name and version + http library's name and version.
fn http_user_agent() -> String {
    format!("{} {}/{}", APP_NAME, APP_VERSION, HTTP_CLIENT_LIB)
}
