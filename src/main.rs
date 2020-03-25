#![deny(clippy::mem_forget)]
use log::{Level, LevelFilter, Metadata, Record};
use std::env;
mod acme;

static LOGGER: Logger = Logger;
struct Logger;

impl log::Log for Logger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= Level::Debug
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            if record.target() == "certifika::acme" {
                println!(
                    "{{\"level\":\"{}\",\"message\":{}}}",
                    record.level(),
                    record.args()
                );
            }
        }
    }
    fn flush(&self) {}
}

#[derive(Debug)]
struct Config {
    base_dir: String,
    log_level: String,
}

fn configure() -> Config {
    let home_dir = env::var("HOME").unwrap();
    Config {
        base_dir: env::var("CERTIFIKA_STORE_DIR")
            .unwrap_or(format!("{}/.config/certifika", home_dir)),
        log_level: env::var("CERTIFIKA_LOG_LEVEL").unwrap_or("info".to_string()),
    }
}

fn main() {
    let config = configure();
    let log_level = match config.log_level.as_str() {
        "debug" => LevelFilter::Debug,
        "warn" => LevelFilter::Warn,
        "error" => LevelFilter::Error,
        _ => LevelFilter::Info,
    };
    log::set_logger(&LOGGER).unwrap();
    log::set_max_level(log_level);

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
