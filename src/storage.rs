use std::env;
use std::fs::File;
use std::io::{Read, Write};
use thiserror::Error;

pub enum ObjectKind {
    Directory,
    KeyPair,
    Account,
}

#[derive(Error, Debug)]
pub enum StoreError {
    #[error("Both VAULT_ADDR and VAULT_TOKEN must be set: {0:?}")]
    Init(env::VarError),
    #[error("Vault API: {0:?}")]
    Vault(ureq::Error),
    #[error("JSON encode: {0:?}")]
    JsonEncode(std::io::Error),
    #[error("Base64 decode: {0:?}")]
    Base64Decode(base64::DecodeError),
    #[error("File I/O: {0:?}")]
    File(std::io::Error),
}

pub trait Store {
    fn read(&self, kind: ObjectKind, account_name: &str) -> Result<Vec<u8>, StoreError>;
    fn write(&self, kind: ObjectKind, account_name: &str, payload: &[u8])
        -> Result<(), StoreError>;
}

pub struct FileStore {
    base_dir: String,
}

pub struct VaultStore {
    addr: String,
    token: String,
    prefix: String,
}

impl VaultStore {
    pub fn init(prefix: &str) -> Result<Self, StoreError> {
        Ok(VaultStore {
            addr: env::var("VAULT_ADDR").map_err(StoreError::Init)?,
            token: env::var("VAULT_TOKEN").map_err(StoreError::Init)?,
            prefix: prefix.to_string(),
        })
    }
    fn put(&self, path: &str, payload: &[u8]) -> Result<(), StoreError> {
        let agent = ureq::AgentBuilder::new().build();
        let url = format!("{}/v1/secret/data/{}", &self.addr, path);
        let _ = agent
            .post(&url)
            .set("X-Vault-Token", &self.token)
            .send_json(ureq::json!({"data": { "value" : base64::encode(payload)}}))
            .map_err(StoreError::Vault)?;
        Ok(())
    }
    fn get(&self, path: &str) -> Result<Vec<u8>, StoreError> {
        let agent = ureq::AgentBuilder::new().build();
        let url = format!("{}/v1/secret/data/{}", &self.addr, path);
        let json: serde_json::Value = agent
            .get(&url)
            .set("X-Vault-Token", &self.token)
            .call()
            .map_err(StoreError::Vault)?
            .into_json()
            .map_err(StoreError::JsonEncode)?;
        let value = &json["data"]["data"]["value"].as_str().unwrap();
        Ok(value.to_string().into_bytes())
    }
}

impl Store for VaultStore {
    fn read(&self, kind: ObjectKind, account_name: &str) -> Result<Vec<u8>, StoreError> {
        let path = match kind {
            ObjectKind::Directory => {
                format!("{}/accounts/{}.dir", self.prefix, account_name)
            }
            ObjectKind::Account => format!("{}/accounts/{}.acc", self.prefix, account_name),
            ObjectKind::KeyPair => format!("{}/accounts/{}.key", self.prefix, account_name),
        };
        let buffer = base64::decode(self.get(&path)?).map_err(StoreError::Base64Decode)?;
        Ok(buffer)
    }

    fn write(
        &self,
        kind: ObjectKind,
        account_name: &str,
        payload: &[u8],
    ) -> Result<(), StoreError> {
        let path = match kind {
            ObjectKind::Directory => {
                format!("{}/accounts/{}.dir", self.prefix, account_name)
            }
            ObjectKind::Account => format!("{}/accounts/{}.acc", self.prefix, account_name),
            ObjectKind::KeyPair => format!("{}/accounts/{}.key", self.prefix, account_name),
        };
        self.put(&path, payload)?;
        Ok(())
    }
}

impl FileStore {
    pub fn init(base_dir: &str) -> Result<Self, StoreError> {
        Ok(FileStore {
            base_dir: base_dir.to_string(),
        })
    }
}

impl Store for FileStore {
    fn read(&self, kind: ObjectKind, account_name: &str) -> Result<Vec<u8>, StoreError> {
        let filename = match kind {
            ObjectKind::Directory => format!("{}/accounts/{}.dir", self.base_dir, account_name),
            ObjectKind::Account => format!("{}/accounts/{}.acc", self.base_dir, account_name),
            ObjectKind::KeyPair => format!("{}/accounts/{}.key", self.base_dir, account_name),
        };
        let mut file = File::open(filename).map_err(StoreError::File)?;
        let mut buffer: Vec<u8> = Vec::new();
        file.read_to_end(&mut buffer).map_err(StoreError::File)?;
        Ok(buffer)
    }

    fn write(
        &self,
        kind: ObjectKind,
        account_name: &str,
        payload: &[u8],
    ) -> Result<(), StoreError> {
        let filename = match kind {
            ObjectKind::Directory => format!("{}/accounts/{}.dir", self.base_dir, account_name),
            ObjectKind::Account => format!("{}/accounts/{}.acc", self.base_dir, account_name),
            ObjectKind::KeyPair => format!("{}/accounts/{}.key", self.base_dir, account_name),
        };
        let mut file = File::create(filename).map_err(StoreError::File)?;
        file.write_all(payload).map_err(StoreError::File)?;
        Ok(())
    }
}
