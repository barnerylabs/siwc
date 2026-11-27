//! The provider's model list. The first two bytes are the status.
#![no_main]

use libfuzzer_sys::fuzz_target;
use siwc::plan::Models;
use siwc_fuzz::response;

fuzz_target!(|data: &[u8]| {
    if let Some(response) = response(data) {
        Models::fuzz_response(&response);
    }
});
