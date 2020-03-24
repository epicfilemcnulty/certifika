#![deny(clippy::mem_forget)]
use std::env;
mod acme;

#[derive(Debug)]
struct Config {
    base_dir: String,
}

fn configure() -> Config {
    let home_dir = env::var("HOME").unwrap();
    Config {
        base_dir: env::var("CERTIFIKA_STORE_DIR")
            .unwrap_or(format!("{}/.config/certifika", home_dir)),
    }
}

fn main() {
    let config = configure();
    let store_type = env::args().nth(1).unwrap();
    let command = env::args().nth(2).unwrap();
    let email = env::args().nth(3).unwrap();

    let store: Box<dyn acme::storage::Store> = match store_type.as_str() {
        "file" => Box::new(acme::storage::FileStore::init(&config.base_dir).unwrap()),
        "db" => Box::new(acme::storage::DbStore::init(&config.base_dir).unwrap()),
        _ => panic!("unknown storage type"),
    };

    let mut account = match command.as_str() {
        "load" => acme::Account::load(email, &*store).unwrap(),
        "reg" => acme::Account::new(email, &*store).unwrap(),
        _ => panic!("Unknown command!"),
    };
    let domains: Vec<String> = ["deviant.guru".to_string()].to_vec();
    account.order(domains).unwrap();
    account.info();
}
