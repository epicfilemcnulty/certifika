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
use reqwest::blocking::Client;
use reqwest::header::USER_AGENT;
use reqwest::StatusCode;
use ring::{
    rand,
    signature::{self, EcdsaKeyPair},
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;

mod jws;
pub mod storage;

/// **RFC8555** says that all ACME clients should send user-agent header,
/// consisting of the client's name and version + http library's name and version.
pub const USER_AGENT_VALUE: &str = "certifika 0.1/reqwest 0.10";
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
        let client = Client::new();
        let res = client
            .get(url)
            .header(USER_AGENT, USER_AGENT_VALUE)
            .send()?;
        Ok(Directory {
            url: url.to_owned(),
            directory: res.json()?,
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

    pub fn order(&mut self, domains: Vec<String>) -> Result<Order, Box<dyn Error>> {
        let mut json = r#"{"identifiers":["#.to_string();
        for domain in domains {
            json.push_str(format!("{{\"type\":\"dns\",\"value\":\"{}\"}},", domain).as_str());
        }
        let _ = json.pop(); // remove the last comma
        json.push_str("]}");
        let p: serde_json::Value = serde_json::from_str(&json).unwrap();
        let (status_code, response) = self
            .request("newOrder", serde_json::to_string(&p).unwrap())
            .unwrap();
        if status_code.is_success() {
            Ok(serde_json::from_str(&response).unwrap())
        } else {
            Err(response.into())
        }
    }

    pub fn info(&mut self) {
        let url = self.kid.as_ref().unwrap().to_owned();
        let (status_code, response) = self.request(&url, "".to_string()).unwrap();
        println!("{}\n{}", status_code, response);
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
        let mut payload = HashMap::new();
        let mut contact: Vec<String> = Vec::new();
        contact.push(format!("mailto:{}", self.email.to_owned())); // <--- probably gotta convert this to string
        payload.insert(
            "termsOfServiceAgreed".to_owned(),
            serde_json::to_value(true)?,
        );
        payload.insert("contact".to_owned(), serde_json::to_value(contact)?);
        let p: serde_json::Value = serde_json::to_value(&payload).unwrap();
        let (status_code, response) = self.request("newAccount", serde_json::to_string(&p)?)?;
        if status_code.is_success() {
            Ok(())
        } else {
            Err(format!("failed to register account - {}", response).into())
        }
    }

    fn get_nonce(&self) -> Result<String, Box<dyn Error>> {
        let url = self.directory.url_for("newNonce").unwrap();
        let client = Client::new();
        let res = client
            .head(url)
            .header(USER_AGENT, USER_AGENT_VALUE)
            .send()?;
        let nonce = res.headers().get("Replay-Nonce").unwrap();
        Ok(nonce.to_str().unwrap().to_string())
    }

    fn request(
        &mut self,
        resource: &str,
        payload: String,
    ) -> Result<(StatusCode, String), Box<dyn Error>> {
        let url = match self.directory.url_for(resource) {
            None => resource,
            Some(u) => u,
        };
        let nonce = self.nonce.as_ref().unwrap();
        let jws = jws::sign(&self.key_pair, &nonce, &url, payload, self.kid.as_deref())?;
        let client = Client::new();
        let req = client
            .post(url)
            .header(USER_AGENT, USER_AGENT_VALUE)
            .header("content-type", "application/jose+json")
            .body(jws);
        let res = req.send()?;
        let nonce = res.headers().get("Replay-Nonce").unwrap();
        self.nonce = Some(nonce.to_str().unwrap().to_string());
        if resource == "newAccount" {
            let kid = res.headers().get("Location").unwrap();
            self.kid = Some(kid.to_str()?.to_string());
        }
        Ok((res.status(), res.text()?))
    }
}
