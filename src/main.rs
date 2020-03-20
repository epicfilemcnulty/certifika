use std::env;
mod acme;

#[derive(Debug)]
struct Config {
    account_dir: String,
    certs_dir: String,
}

fn main() {
    let home_dir = env::var("HOME").unwrap();
    let config = Config {
        account_dir: env::var("CERTIFIKA_ACCOUNT_DIR")
            .unwrap_or(format!("{}/.config/certifika/accounts", home_dir).to_string()),
        certs_dir: env::var("CERTIFIKA_CERTS_DIR")
            .unwrap_or(format!("{}/.config/certifika/certs", home_dir).to_string()),
    };
    let command = env::args().nth(1).unwrap();
    let name = env::args().nth(2).unwrap();
    let mut account = match command.as_str() {
        "load" => acme::Account::load(&config.account_dir, &name).unwrap(),
        "reg" =>  acme::Account::new(&config.account_dir, &name).unwrap(),
        _ => panic!("Unknown command!"),
    };
    account.info();
}
