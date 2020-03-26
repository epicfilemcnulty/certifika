//! module to work with Let's Encrypt API, i.e. ACME protocol ([RFC8555](https://tools.ietf.org/html/rfc8555))
//!
//! Provides all basics objects and methods to register a new ACME account, order
//! and fetch certificates.
//!
//! # Examples
//!
//! ## Register a new account
//! ```
//! let store = acme::storage::FileStore::init(&"/tmp/certifika").unwrap()
//! let account = acme::Account::new("some@email.com".as_str(), &store).unwrap();
//! ```
use ring::{
    digest, rand,
    signature::{self, EcdsaKeyPair, KeyPair},
};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::{thread, time};

mod jws;
pub mod storage;

/// **RFC8555** says that all ACME clients should send user-agent header,
/// consisting of the client's name and version + http library's name and version.
pub const USER_AGENT: &str = "certifika 0.1/ureq 0.12.0";
pub const LETSENCRYPT_DIRECTORY_URL: &str =
    "https://acme-staging-v02.api.letsencrypt.org/directory";

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
    pub fn lets_encrypt() -> Result<Directory, Box<dyn Error>> {
        Directory::from_url(LETSENCRYPT_DIRECTORY_URL)
    }
    /// method to create a new Directory instance from an URL.
    pub fn from_url(url: &str) -> Result<Directory, Box<dyn Error>> {
        let agent = ureq::agent().set("User-Agent", USER_AGENT).build();
        let response = agent.get(url).call();
        if response.ok() {
            Ok(Directory {
                url: url.to_owned(),
                directory: response.into_json()?,
            })
        } else {
            Err(response.into_string()?.into())
        }
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
    store: &'a dyn storage::Store,
    email: String,
    directory: Directory,
    key_pair: EcdsaKeyPair,
    pkcs8: Vec<u8>,
    nonce: Option<String>,
    kid: Option<String>,
}

impl<'a> Account<'a> {
    /// Tries to register a new ACME account.
    pub fn new(
        email: String,
        store: &'a dyn storage::Store,
    ) -> Result<Account<'a>, Box<dyn Error>> {
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
        match &acc.register() {
            Ok(_) => {
                acc.save()?;
                Ok(acc)
            }
            Err(_) => Err("failed to register account".into()),
        }
    }

    pub fn save(&self) -> Result<(), Box<dyn Error>> {
        self.store.write(
            storage::ObjectKind::KeyPair,
            &self.email,
            self.pkcs8.as_ref(),
        )?;
        self.store.write(
            storage::ObjectKind::Account,
            &self.email,
            self.kid.to_owned().unwrap().as_bytes(),
        )?;
        let payload = serde_json::to_string(&self.directory)?;
        self.store.write(
            storage::ObjectKind::Directory,
            &self.email,
            payload.as_bytes(),
        )?;
        Ok(())
    }

    pub fn load(
        email: String,
        store: &'a dyn storage::Store,
    ) -> Result<Account<'a>, Box<dyn Error>> {
        let alg = &signature::ECDSA_P256_SHA256_FIXED_SIGNING;
        let pkcs8 = store.read(storage::ObjectKind::KeyPair, &email)?;
        let key_pair = signature::EcdsaKeyPair::from_pkcs8(alg, pkcs8.as_ref()).unwrap();
        let dir = serde_json::from_slice(&store.read(storage::ObjectKind::Directory, &email)?)?;
        let mut acc = Account {
            email,
            directory: dir,
            store,
            key_pair,
            pkcs8,
            nonce: None,
            kid: None,
        };
        acc.nonce = Some(acc.get_nonce().unwrap());
        acc.kid = Some(
            std::str::from_utf8(&acc.store.read(storage::ObjectKind::Account, &acc.email)?)?
                .to_string(),
        );
        Ok(acc)
    }

    pub fn order(&mut self, domains: Vec<String>) -> Result<(), Box<dyn Error>> {
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
        let payload = serde_json::to_string(&OrderReq { identifiers: ids })?;
        let (status_code, response) = self.request("newOrder", payload).unwrap();
        if http_status_ok(status_code) {
            let order: Order = serde_json::from_str(&response).unwrap();
            for auth in &order.authorizations {
                let a = self.authorization(&auth).unwrap();
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
            Err(response.into())
        }
    }

    fn authorization(&mut self, url: &str) -> Result<Authorization, Box<dyn Error>> {
        let (status_code, response) = self.request(url, "".to_string()).unwrap();
        if http_status_ok(status_code) {
            Ok(serde_json::from_str(&response).unwrap())
        } else {
            Err(response.into())
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
    fn generate_keypair() -> Result<(EcdsaKeyPair, Vec<u8>), Box<dyn Error>> {
        // Generate a key pair in PKCS#8 (v2) format.
        let rng = rand::SystemRandom::new();
        let alg = &signature::ECDSA_P256_SHA256_FIXED_SIGNING;
        let pkcs8 = signature::EcdsaKeyPair::generate_pkcs8(alg, &rng).unwrap();
        let key_pair = signature::EcdsaKeyPair::from_pkcs8(alg, pkcs8.as_ref()).unwrap();
        Ok((key_pair, pkcs8.as_ref().to_owned()))
    }

    fn register(&mut self) -> Result<(), Box<dyn Error>> {
        #[derive(Debug, Serialize, Deserialize)]
        struct Registration {
            contact: Vec<String>,
            #[serde(rename = "termsOfServiceAgreed")]
            terms_of_service_agreed: bool,
        }
        let payload = serde_json::to_string(&Registration {
            contact: vec![format!("mailto:{}", self.email.to_owned())],
            terms_of_service_agreed: true,
        })?;
        let (status_code, response) = self.request("newAccount", payload)?;
        if http_status_ok(status_code) {
            Ok(())
        } else {
            Err(format!("failed to register account - {}", response).into())
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

    fn get_nonce(&self) -> Result<String, Box<dyn Error>> {
        let url = self.directory.url_for("newNonce").unwrap();
        let agent = ureq::agent().set("User-Agent", USER_AGENT).build();
        let response = agent.head(url).call();
        if response.ok() {
            let nonce = response.header("Replay-Nonce").unwrap();
            Ok(nonce.to_string())
        } else {
            Err(response.into_string()?.into())
        }
    }

    fn request(
        &mut self,
        resource: &str,
        payload: String,
    ) -> Result<(u16, String), Box<dyn Error>> {
        let url = match self.directory.url_for(resource) {
            None => resource,
            Some(u) => u,
        };
        let nonce = self.nonce.as_ref().unwrap();
        let body = if payload.len() > 0 {
            payload.clone()
        } else {
            "\"\"".to_string()
        };
        log::debug!(r#"{{"op":"request","url":"{}","body":{}}}"#, url, body);
        let jws = jws::sign(&self.key_pair, &nonce, &url, payload, self.kid.as_deref())?;
        let agent = ureq::agent()
            .set("User-Agent", USER_AGENT)
            .set("Content-Type", "application/jose+json")
            .build();
        let response = agent.post(url).send_string(&jws);
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
            Ok((response.status(), response.into_string()?))
        } else {
            Err(response.into_string()?.into())
        }
    }
}

fn http_status_ok(status: u16) -> bool {
    status >= 200 && status < 300
}
