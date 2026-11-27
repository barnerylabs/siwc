//! A buffered API refusal. The first two bytes are the status.
#![no_main]

use libfuzzer_sys::fuzz_target;
use siwc::plan::Refusal;
use siwc_fuzz::response;

fuzz_target!(|data: &[u8]| {
    if let Some(response) = response(data) {
        Refusal::fuzz_response(&response);
    }
});
