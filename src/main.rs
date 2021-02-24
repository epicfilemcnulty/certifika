#![deny(clippy::mem_forget)]
use anyhow::{anyhow, Context, Result};
use std::env;
mod acme;
mod config;
mod log;
mod storage;

pub const APP_NAME: &str = "certifika";
pub const APP_VERSION: &str = "0.1.0";

fn main() -> Result<()> {
    let config = config::Config::parse()?;
    crate::log::init(config.log_level);

    let command = env::args().nth(1).context("command not provided")?;
    let email = env::args().nth(2).context("account email not provided")?;
    let mut account = match command.as_str() {
        "load" => acme::Account::load(email, &*config.store)?,
        "reg" => acme::Account::new(email, &*config.store)?,
        _ => return Err(anyhow!("Unknown command!")),
    };
    let domains: Vec<String> = ["deviantguru".to_string()].to_vec();
    account.order(domains)?;
    account.info();
    Ok(())
}
