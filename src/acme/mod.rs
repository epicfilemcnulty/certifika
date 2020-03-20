use reqwest::blocking::Client;
use reqwest::header::USER_AGENT;
use reqwest::StatusCode;
use ring::{
    rand,
    signature::{self, EcdsaKeyPair},
};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::error::Error;
use std::fs::File;
use std::io::{Read, Write};

mod jws;

pub const USER_AGENT_VALUE: &'static str = "certifika 0.1/reqwest 0.10";
pub const LETSENCRYPT_DIRECTORY_URL: &'static str =
    "https://acme-staging-v02.api.letsencrypt.org/directory";

#[derive(Debug, Serialize, Deserialize)]
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
        Ok(Directory {
            url: url.to_owned(),
            directory: res.json()?,
        })
    }

    fn save(&self, filename: &str) -> Result<(), Box<dyn Error>>{
        let file = File::create(filename)?;
        serde_cbor::to_writer(file, self)?;
        Ok(())
    }
    
    fn load(filename: &str) ->Result<Self, Box<dyn Error>>{
        let file = File::open(filename)?;
        let dir: Directory = serde_cbor::from_reader(file).unwrap();
        Ok(dir)
    }

    /// Returns url for the resource.
    fn url_for(&self, resource: &str) -> Option<&str> {
        self.directory
            .as_object()
            .and_then(|o| o.get(resource))
            .and_then(|k| k.as_str())
    }

}

pub struct Account {
    pub directory: Directory,
    key_pair: EcdsaKeyPair,
    pkcs8: Vec<u8>,
    nonce: Option<String>,
    pub kid: Option<String>,
}

impl Account {

    pub fn new(account_dir: &str, name: &str) -> Result<Account, Box<dyn Error>> {
        let (kp, pk) = Account::generate_keypair()?;
        let mut acc = Account {
            directory: Directory::lets_encrypt()?,
            key_pair: kp,
            pkcs8: pk,
            nonce: None,
            kid: None
        };
        acc.nonce = Some(acc.get_nonce()?);
        match &acc.register(name) {
            Ok(_) => { 
                acc.save(account_dir, name)?;
                Ok(acc)
                },
            Err(_) => Err("failed to register account".into()),
        }
                
    }

    pub fn load(account_dir: &str, name: &str) -> Result<Account, Box<dyn Error>>{
        let (kp, pk) = Account::load_keypair(format!("{}/{}.key", account_dir, name).as_str())?;
        let account_id = std::fs::read_to_string(&format!("{}/{}.acc", account_dir, name))?;
        let mut account = Account {
            directory: Directory::load(format!("{}/{}.dir", account_dir, name).as_str())?,
            key_pair: kp,
            pkcs8: pk,
            nonce: None,
            kid: Some(account_id),
        };
        account.nonce = Some(account.get_nonce().unwrap());
        Ok(account)
    }

    pub fn save(&self, account_dir: &str, name: &str) -> Result<(), Box<dyn Error>> {
        std::fs::write(&format!("{}/{}.acc", account_dir, name), self.kid.to_owned().unwrap())?;
        self.save_keypair(&format!("{}/{}.key", account_dir, name))?;
        self.directory.save(&format!("{}/{}.dir", account_dir, name))?;
        Ok(())
    }

    pub fn info(&mut self) {
        println!("kid: {}", self.kid.as_ref().unwrap());
        println!("nonce: {}", self.nonce.as_ref().unwrap());
    }

    pub fn order(&mut self) {
        let json = r#"
            { "identifiers": [ { "type": "dns", "value": "deviant.guru" }] }
        "#;
        let payload: serde_json::Value = serde_json::from_str(&json).unwrap();
        let (status_code, response) = self
            .request("newOrder", &payload)
            .unwrap();
        println!("status, resp: {} {:?}", status_code, response);
        println!("directory: {}", self.directory.directory.to_string());
    }

    fn generate_keypair() -> Result<(EcdsaKeyPair, Vec<u8>), Box<dyn Error>> {
        // Generate a key pair in PKCS#8 (v2) format.
        let rng = rand::SystemRandom::new();
        let alg = &signature::ECDSA_P256_SHA256_FIXED_SIGNING;
        let pkcs8 = signature::EcdsaKeyPair::generate_pkcs8(alg, &rng).unwrap();
        let key_pair = signature::EcdsaKeyPair::from_pkcs8(alg, pkcs8.as_ref()).unwrap();
        Ok((key_pair, pkcs8.as_ref().to_owned()))
    }

    fn load_keypair(filename: &str) -> Result<(EcdsaKeyPair, Vec<u8>), Box<dyn Error>> {
        let mut file = File::open(filename)?;
        let mut pkcs8: Vec<u8> = Vec::new();
        file.read_to_end(&mut pkcs8)?;
        let alg = &signature::ECDSA_P256_SHA256_FIXED_SIGNING;
        Ok(
            (signature::EcdsaKeyPair::from_pkcs8(alg, pkcs8.as_slice()).unwrap(),
            pkcs8)
        )
    }

    fn save_keypair(&self, filename: &str) -> Result<(), Box<dyn Error>> {
        let mut file = File::create(filename)?;
        file.write_all(self.pkcs8.as_ref())?;
        Ok(())
    }

    fn register(&mut self, email: &str) -> Result<(), Box<dyn Error>> {
        let mut payload = HashMap::new();
        let mut contact: Vec<String> = Vec::new();
        contact.push(format!("mailto:{}", email.to_owned())); // <--- probably gotta convert this to string
        payload.insert(
            "termsOfServiceAgreed".to_owned(),
            serde_json::to_value(true)?,
        );
        payload.insert("contact".to_owned(), serde_json::to_value(contact)?);
        let (status_code, response) =
            self.request("newAccount", payload)?;
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

    fn request<T: Serialize>(
        &mut self,
        resource: &str,
        payload: T,
    ) -> Result<(StatusCode, serde_json::Value), Box<dyn Error>> {
        //let json = serde_json::to_value(&payload)?;

        let url = match self.directory.url_for(resource) {
            None => resource,
            Some(u) => u,
        };
        let nonce = self.nonce.as_ref().unwrap();
        let kid = match &self.kid {
            None => "",
            Some(k) => &k,
        };
        let jws = jws::sign(&self.key_pair, &nonce, &url, &payload, kid)?;
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
            self.kid = Some(kid.to_str().unwrap().to_string());
        }
        Ok((res.status(), res.json()?))
    }
}
