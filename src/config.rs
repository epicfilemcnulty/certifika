#![deny(clippy::mem_forget)]
use ::log::LevelFilter;
use std::env;

pub struct Config {
    pub store: Box<dyn crate::storage::Store>,
    pub log_level: LevelFilter,
}

impl Config {
    pub fn parse() -> Self {
        let home_dir = env::var("HOME").unwrap();
        let base_dir =
            env::var("CERTIFIKA_STORE_DIR").unwrap_or(format!("{}/.config/certifika", home_dir));
        let log_level = match env::var("CERTIFIKA_LOG_LEVEL")
            .unwrap_or_else(|_| "WARN".to_string())
            .as_str()
        {
            "DEBUG" => LevelFilter::Debug,
            "INFO" => LevelFilter::Info,
            "WARN" => LevelFilter::Warn,
            "ERROR" => LevelFilter::Error,
            _ => LevelFilter::Info,
        };
        let store: Box<dyn crate::storage::Store> = match env::var("CERTIFIKA_STORE_TYPE")
            .unwrap_or_else(|_| "file".to_string())
            .as_str()
        {
            "file" => Box::new(crate::storage::FileStore::init(&base_dir).unwrap()),
            "vault" => Box::new(crate::storage::VaultStore::init("certifika").unwrap()),
            _ => panic!("unknown storage type"),
        };
        Config { log_level, store }
    }
}
