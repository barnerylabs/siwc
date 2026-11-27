//! The provider's published key set.
#![no_main]

use libfuzzer_sys::fuzz_target;
use siwc::protocol::{HttpResponse, Jwks};

fuzz_target!(|body: &[u8]| {
    let _keys = Jwks::from_response(&HttpResponse::new(200, body.to_vec()));
});
