#![deny(clippy::mem_forget)]
use std::env;
mod acme;
mod config;
mod log;

pub const APP_NAME: &str = "certifika";

fn main() {
    let config = config::Config::parse();
    crate::log::init(config.log_level);

    let command = env::args().nth(1).unwrap();
    let email = env::args().nth(2).unwrap();

    let mut account = match command.as_str() {
        "load" => acme::Account::load(email, &*config.store).unwrap(),
        "reg" => acme::Account::new(email, &*config.store).unwrap(),
        _ => panic!("Unknown command!"),
    };
    let domains: Vec<String> = ["deviant.guru".to_string()].to_vec();
    account.order(domains).unwrap();
    account.info();
}
