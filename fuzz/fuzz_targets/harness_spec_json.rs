#![no_main]

use libfuzzer_sys::fuzz_target;
use nyx_agent_nyx::harness_spec::HarnessSpec;

fuzz_target!(|data: &[u8]| {
    let Ok(raw) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok((spec, canonical)) = HarnessSpec::from_json(raw) {
        let _ = spec.validate();
        let _ = HarnessSpec::from_json(&canonical);
    }
});
