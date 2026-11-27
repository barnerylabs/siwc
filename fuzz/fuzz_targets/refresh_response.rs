//! The response to a token renewal. The first two bytes are the status.
#![no_main]

use libfuzzer_sys::fuzz_target;
use siwc_fuzz::{NOW, credentials, response};

fuzz_target!(|data: &[u8]| {
    if let Some(response) = response(data) {
        credentials().fuzz_refresh_response(response, NOW);
    }
});
