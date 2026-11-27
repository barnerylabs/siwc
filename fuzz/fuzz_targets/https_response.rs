//! An HTTP/1.x response read by the built-in `https` transport, arriving in
//! pieces.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| siwc::https::fuzz_response(data));
