#![no_main]

use libfuzzer_sys::fuzz_target;
use nyctos_types::live_plan::LiveTestPlan;

fuzz_target!(|data: &[u8]| {
    let Ok(raw) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(plan) = serde_json::from_str::<LiveTestPlan>(raw) {
        let _ = plan.validate();
        let _ = serde_json::to_string(&plan);
    }
});
