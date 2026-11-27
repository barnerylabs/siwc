//! The provider's answer to the code exchange, and the ID token in it.
//! The first two bytes are the status.
#![no_main]

use libfuzzer_sys::fuzz_target;
use siwc::protocol::HttpResponse;
use siwc_fuzz::{NOW, exchange, keys};

fuzz_target!(|data: &[u8]| {
    siwc::fuzz_stored_records(data);
    let Some((status, body)) = data.split_first_chunk::<2>() else {
        return;
    };
    let response = HttpResponse::new(u16::from_be_bytes(*status), body.to_vec());
    if let Ok(unverified) = exchange().response(response, NOW) {
        let _signed_in = unverified.verify(&keys(), NOW);
    }
});
