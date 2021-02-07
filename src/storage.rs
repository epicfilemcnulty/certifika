use base64;
use hashicorp_vault as vault;
use std::env;
use std::error::Error;
use std::fs::File;
use std::io::{Read, Write};

pub enum ObjectKind {
    Directory,
    KeyPair,
    Account,
}

pub trait Store {
    fn read(&self, kind: ObjectKind, account_name: &str) -> Result<Vec<u8>, Box<dyn Error>>;
    fn write(
        &self,
        kind: ObjectKind,
        account_name: &str,
        payload: &[u8],
    ) -> Result<(), Box<dyn Error>>;
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
    pub fn init(prefix: &str) -> Result<Self, Box<dyn Error>> {
        Ok(VaultStore {
            addr: env::var("VAULT_ADDR")?,
            token: env::var("VAULT_TOKEN")?,
            prefix: prefix.to_string(),
        })
    }
    fn put(&self, path: &str, payload: &[u8]) -> Result<(), Box<dyn Error>> {
        let agent = ureq::AgentBuilder::new().build();
        let url = format!("{}/v1/secret/data/{}", &self.addr, path);
        let _ = agent
            .post(&url)
            .set("X-Vault-Token", &self.token)
            .send_bytes(payload)?;
        Ok(())
    }
}

impl Store for VaultStore {
    fn read(&self, kind: ObjectKind, account_name: &str) -> Result<Vec<u8>, Box<dyn Error>> {
        let path = match kind {
            ObjectKind::Directory => {
                format!("{}/accounts/{}.dir", self.prefix, account_name)
            }
            ObjectKind::Account => format!("{}/accounts/{}.acc", self.prefix, account_name),
            ObjectKind::KeyPair => format!("{}/accounts/{}.key", self.prefix, account_name),
        };
        let client = vault::Client::new(&self.addr, &self.token)?;
        let buffer = base64::decode(client.get_secret(path)?)?;
        Ok(buffer)
    }

    fn write(
        &self,
        kind: ObjectKind,
        account_name: &str,
        payload: &[u8],
    ) -> Result<(), Box<dyn Error>> {
        let path = match kind {
            ObjectKind::Directory => {
                format!("{}/accounts/{}.dir", self.prefix, account_name)
            }
            ObjectKind::Account => format!("{}/accounts/{}.acc", self.prefix, account_name),
            ObjectKind::KeyPair => format!("{}/accounts/{}.key", self.prefix, account_name),
        };
        let client = vault::Client::new(&self.addr, &self.token)?;
        client.set_secret(path, base64::encode(payload))?;
        Ok(())
    }
}

impl FileStore {
    pub fn init(base_dir: &str) -> Result<Self, Box<dyn Error>> {
        Ok(FileStore {
            base_dir: base_dir.to_string(),
        })
    }
}

impl Store for FileStore {
    fn read(&self, kind: ObjectKind, account_name: &str) -> Result<Vec<u8>, Box<dyn Error>> {
        let filename = match kind {
            ObjectKind::Directory => format!("{}/accounts/{}.dir", self.base_dir, account_name),
            ObjectKind::Account => format!("{}/accounts/{}.acc", self.base_dir, account_name),
            ObjectKind::KeyPair => format!("{}/accounts/{}.key", self.base_dir, account_name),
        };
        let mut file = File::open(filename)?;
        let mut buffer: Vec<u8> = Vec::new();
        file.read_to_end(&mut buffer)?;
        Ok(buffer)
    }

    fn write(
        &self,
        kind: ObjectKind,
        account_name: &str,
        payload: &[u8],
    ) -> Result<(), Box<dyn Error>> {
        let filename = match kind {
            ObjectKind::Directory => format!("{}/accounts/{}.dir", self.base_dir, account_name),
            ObjectKind::Account => format!("{}/accounts/{}.acc", self.base_dir, account_name),
            ObjectKind::KeyPair => format!("{}/accounts/{}.key", self.base_dir, account_name),
        };
        let mut file = File::create(filename)?;
        file.write_all(payload)?;
        Ok(())
    }
}
