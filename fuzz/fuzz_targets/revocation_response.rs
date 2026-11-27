//! The response to a revocation. The first two bytes are the status.
#![no_main]

use libfuzzer_sys::fuzz_target;
use siwc_fuzz::{credentials, response};

fuzz_target!(|data: &[u8]| {
    if let Some(response) = response(data) {
        credentials().fuzz_revocation_response(&response);
    }
});
