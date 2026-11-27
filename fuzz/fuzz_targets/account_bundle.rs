//! An exported account bundle envelope or inner payload read by `AccountBundle`.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| siwc::fuzz_account_bundle(data));
