#![no_main]

use std::path::Path;

use libfuzzer_sys::fuzz_target;
use nyctos_core::config::Config;

fuzz_target!(|data: &[u8]| {
    let Ok(raw) = std::str::from_utf8(data) else {
        return;
    };
    let _ = Config::parse(raw, Path::new("fuzz/nyctos.toml"));
});
