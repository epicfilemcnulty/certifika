use std::error::Error;
use std::fs::File;
use std::io::{Read, Write};

pub enum ObjectKind {
    Directory,
    KeyPair,
    Account,
}

pub trait StoreOps {
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

pub struct DbStore {
    db: sled::Db,
}

impl FileStore {
    pub fn init(base_dir: &str) -> Result<Self, Box<dyn Error>> {
        Ok(FileStore {
            base_dir: base_dir.to_string(),
           })
    }
}

impl StoreOps for FileStore {
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

impl DbStore {
    pub fn init(base_dir: &str) -> Result<Self, Box<dyn Error>> {
        let db_path = format!("{}/sled", base_dir);
        Ok(DbStore {
            db: sled::open(db_path)?,
        })
    }
}

impl StoreOps for DbStore {
    fn read(&self, kind: ObjectKind, account_name: &str) -> Result<Vec<u8>, Box<dyn Error>> {
        let key = match kind {
            ObjectKind::Directory => format!("acc:dir:{}", account_name),
            ObjectKind::Account => format!("acc:url:{}", account_name),
            ObjectKind::KeyPair => format!("acc:key:{}", account_name),
        };
        let mut buffer: Vec<u8> = Vec::new();
        buffer = self.db.get(&key.as_bytes()).unwrap().unwrap().to_vec();
        Ok(buffer)
    }
    fn write(
        &self,
        kind: ObjectKind,
        account_name: &str,
        payload: &[u8],
    ) -> Result<(), Box<dyn Error>> {
        let key = match kind {
            ObjectKind::Directory => format!("acc:dir:{}", account_name),
            ObjectKind::Account => format!("acc:url:{}", account_name),
            ObjectKind::KeyPair => format!("acc:key:{}", account_name),
        };
        match self.db.insert(&key.as_bytes(), payload) {
            Ok(_) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}
