#![deny(clippy::mem_forget)]
use crate::APP_NAME;
use log::{Level, LevelFilter, Metadata, Record};

static LOGGER: Logger = Logger;
struct Logger;

impl log::Log for Logger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= Level::Debug
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            if record.target().starts_with(APP_NAME) {
                println!(
                    r#"{{"level":"{}","message":{}}}"#,
                    record.level(),
                    record
                        .args()
                        .to_string()
                        .replace("\n", "")
                        .replace("\t", "")
                        .replace(" ", "")
                );
            }
        }
    }
    fn flush(&self) {}
}

pub fn init(log_level: LevelFilter) {
    log::set_logger(&LOGGER).unwrap();
    log::set_max_level(log_level);
}
