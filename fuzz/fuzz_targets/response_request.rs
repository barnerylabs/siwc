//! The body of a plan request built from JSON text or from plain texts: a
//! request that is accepted is one JSON object within the size limit that
//! says `"store": false` and `"stream": true`.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| siwc::plan::fuzz_request(data));
