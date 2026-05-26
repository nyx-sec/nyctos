#![no_main]

use std::path::Path;

use libfuzzer_sys::fuzz_target;
use nyx_agent_core::config::Config;

fuzz_target!(|data: &[u8]| {
    let Ok(raw) = std::str::from_utf8(data) else {
        return;
    };
    let _ = Config::parse(raw, Path::new("fuzz/nyx-agent.toml"));
});
