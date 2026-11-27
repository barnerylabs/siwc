//! The head of an HTTP request to the loopback listener, which any local
//! program can send, arriving in pieces.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| siwc::loopback::fuzz_request_head(data));
